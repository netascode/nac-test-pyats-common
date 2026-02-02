# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""APIC authentication module for Cisco ACI (Application Centric Infrastructure).

This module provides authentication functionality for Cisco APIC (Application Policy
Infrastructure Controller), which is the central management and policy enforcement
point for ACI fabric. The authentication mechanism uses REST API calls to obtain
session tokens that are valid for a limited time period.

The module implements a two-tier API design:
1. authenticate() - Low-level method that performs direct APIC authentication
2. get_token() - High-level method that leverages caching for efficient token reuse

This design ensures efficient token management by reusing valid tokens and only
re-authenticating when necessary, reducing unnecessary API calls to the APIC controller.

Note on Fork Safety:
    This module uses urllib instead of httpx for synchronous authentication requests.
    httpx is NOT fork-safe on macOS - creating httpx.Client after fork() causes
    silent crashes due to OpenSSL threading issues. urllib uses simpler primitives
    that work correctly after fork().
"""

from nac_test.pyats_core.common.auth_cache import AuthCache
from nac_test.pyats_core.common.subprocess_auth import (
    execute_auth_subprocess,
)

# Default token lifetime for APIC authentication tokens in seconds
# APIC tokens are typically valid for 10 minutes (600 seconds) by default
APIC_TOKEN_LIFETIME_SECONDS: int = 600

# HTTP timeout for authentication request
AUTH_REQUEST_TIMEOUT_SECONDS: float = 30.0


class APICAuth:
    """APIC-specific authentication implementation with token caching.

    This class provides a two-tier API for APIC authentication:

    1. Low-level authenticate() method: Directly authenticates with APIC and returns
       a token along with its expiration time. This is typically used by the caching
       layer and not called directly by consumers.

    2. High-level get_token() method: Provides cached token management, automatically
       handling token renewal when expired. This is the primary method that consumers
       should use for obtaining APIC tokens.

    The two-tier design ensures efficient token reuse across multiple API calls while
    maintaining clean separation between authentication logic and caching concerns.
    """

    @staticmethod
    def authenticate(url: str, username: str, password: str) -> tuple[str, int]:
        """Perform direct APIC authentication and obtain a session token.

        This method performs a direct authentication request to the APIC controller
        using the provided credentials. It returns both the token and its lifetime
        for proper cache management.

        Internally uses execute_auth_subprocess() to run authentication in a clean
        subprocess, avoiding the macOS fork+SSL crash issue where SSL operations
        crash after fork().

        Args:
            url: Base URL of the APIC controller (e.g., "https://apic.example.com").
                Should not include trailing slashes or API paths.
            username: APIC username for authentication. This should be a valid user
                configured in the APIC with appropriate permissions.
            password: Password for the specified APIC user account.

        Returns:
            A tuple containing:
                - token (str): The APIC session token that should be included in
                  subsequent API requests as a cookie (APIC-cookie).
                - expires_in (int): Token lifetime in seconds (typically 600 seconds).

        Raises:
            SubprocessAuthError: If authentication subprocess fails or returns an error.
            ValueError: If the APIC response contains malformed JSON or unexpected
                structure that cannot be properly parsed.

        Note:
            SSL verification is disabled to handle self-signed certificates commonly
            used in lab and development APIC deployments. In production environments,
            proper certificate validation should be enabled.
        """
        # Build auth parameters for subprocess
        auth_params = {
            "url": url,
            "username": username,
            "password": password,
            "timeout": AUTH_REQUEST_TIMEOUT_SECONDS,
        }

        # APIC-specific authentication logic
        # This script assumes `params` dict is already loaded by execute_auth_subprocess
        auth_script_body = """
import json
import ssl
import urllib.request
import urllib.error

url = params["url"]
username = params["username"]
password = params["password"]
timeout = params["timeout"]

try:
    # Create SSL context with verification disabled
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    # Build JSON payload for APIC authentication
    payload = json.dumps({
        "aaaUser": {
            "attributes": {
                "name": username,
                "pwd": password
            }
        }
    }).encode("utf-8")

    # Create request with proper headers
    request = urllib.request.Request(
        f"{url}/api/aaaLogin.json",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    # Create HTTPS handler with SSL context
    https_handler = urllib.request.HTTPSHandler(context=ssl_context)
    opener = urllib.request.build_opener(https_handler)

    # Execute authentication request
    response = opener.open(request, timeout=timeout)
    response_body = response.read().decode("utf-8")
    response_data = json.loads(response_body)

    # Extract token from response
    token = response_data["imdata"][0]["aaaLogin"]["attributes"]["token"]
    result = {"token": token}

except urllib.error.HTTPError as e:
    error_body = e.read().decode("utf-8") if e.fp else ""
    result = {
        "error": f"HTTP {e.code}: {e.reason}",
        "response": error_body[:500]
    }
except (KeyError, IndexError) as e:
    result = {
        "error": f"Unexpected response structure: {str(e)}",
        "response": response_body[:500] if "response_body" in dir() else ""
    }
except Exception as e:
    result = {"error": str(e)}
"""

        # Execute authentication in subprocess
        auth_data = execute_auth_subprocess(auth_params, auth_script_body)

        return auth_data["token"], APIC_TOKEN_LIFETIME_SECONDS

    @classmethod
    def get_token(cls, url: str, username: str, password: str) -> str:
        """Get APIC token with automatic caching and renewal.

        This is the primary method that consumers should use to obtain APIC tokens.
        It leverages the AuthCache to efficiently manage token lifecycle, reusing
        valid tokens and automatically renewing expired ones. This significantly
        reduces the number of authentication requests to the APIC controller.

        The method uses a cache key based on the controller type ("ACI"), URL,
        and username to ensure proper token isolation between different APIC
        instances and user accounts.

        Args:
            url: Base URL of the APIC controller (e.g., "https://apic.example.com").
                Should not include trailing slashes or API paths.
            username: APIC username for authentication. This should be a valid user
                configured in the APIC with appropriate permissions.
            password: Password for the specified APIC user account.

        Returns:
            A valid APIC session token that can be used in API requests.
            The token should be included as a cookie (APIC-cookie) in subsequent
            API calls to the APIC controller.

        Raises:
            httpx.HTTPStatusError: If the APIC returns a non-2xx status code during
                authentication, typically indicating invalid credentials (401) or
                server issues (5xx).
            httpx.RequestError: If the request fails due to network issues,
                connection timeouts, or other transport-level problems.
            ValueError: If the APIC response contains malformed or unexpected JSON
                structure that cannot be properly parsed.

        Examples:
            >>> # Get a token for APIC access
            >>> token = APICAuth.get_token(
            ...     url="https://apic.example.com",
            ...     username="admin",
            ...     password="password123"
            ... )
            >>> # Use the token in subsequent API calls
            >>> headers = {"Cookie": f"APIC-cookie={token}"}
        """
        # AuthCache.get_or_create_token returns str, but mypy can't verify this
        # because nac_test lacks py.typed marker. The return type is guaranteed
        # by AuthCache's implementation which uses extract_token=True mode.
        return AuthCache.get_or_create_token(  # type: ignore[no-any-return]
            controller_type="ACI",
            url=url,
            username=username,
            password=password,
            auth_func=cls.authenticate,
        )
