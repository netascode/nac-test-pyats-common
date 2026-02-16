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

import os

from nac_test.pyats_core.common.auth_cache import AuthCache
from nac_test.pyats_core.common.subprocess_auth import (
    SubprocessAuthError,  # noqa: F401 - re-exported for callers to catch
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
    def authenticate(
        url: str, username: str, password: str, verify_ssl: bool = False
    ) -> tuple[str, int]:
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
            verify_ssl: Whether to verify SSL certificates. Defaults to False for
                backward compatibility with lab environments using self-signed certs.

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
            SSL verification defaults to disabled to handle self-signed certificates
            commonly used in lab and development APIC deployments. Set verify_ssl=True
            for production environments with proper certificate validation.
        """
        # Build auth parameters for subprocess
        auth_params = {
            "url": url,
            "username": username,
            "password": password,
            "timeout": AUTH_REQUEST_TIMEOUT_SECONDS,
            "verify_ssl": verify_ssl,
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
verify_ssl = params["verify_ssl"]

try:
    # Create SSL context
    ssl_context = ssl.create_default_context()
    if not verify_ssl:
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
    def get_token(
        cls, url: str, username: str, password: str, verify_ssl: bool = False
    ) -> str:
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
            verify_ssl: Whether to verify SSL certificates. Defaults to False for
                backward compatibility with lab environments using self-signed certs.

        Returns:
            A valid APIC session token that can be used in API requests.
            The token should be included as a cookie (APIC-cookie) in subsequent
            API calls to the APIC controller.

        Raises:
            SubprocessAuthError: If authentication fails due to invalid credentials,
                network issues, connection timeouts, or APIC server errors. The error
                message will contain details from the authentication subprocess.

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
            auth_func=lambda u, un, pw: cls.authenticate(u, un, pw, verify_ssl),
        )

    @classmethod
    def get_auth(cls) -> str:
        """Get APIC token with automatic caching, using environment variables.

        This is the primary method that consumers should use to obtain APIC tokens
        when using environment variable configuration. It leverages the AuthCache
        to efficiently manage token lifecycle.

        Environment Variables Required:
            ACI_URL: Base URL of the APIC controller
            ACI_USERNAME: APIC username for authentication
            ACI_PASSWORD: APIC password for authentication
            ACI_INSECURE: Optional. Set to "True" to disable SSL verification
                (default: True for backward compatibility)

        Returns:
            A valid APIC session token.

        Raises:
            ValueError: If required environment variables are not set.
        """
        url = os.environ.get("ACI_URL")
        username = os.environ.get("ACI_USERNAME")
        password = os.environ.get("ACI_PASSWORD")
        insecure = os.environ.get("ACI_INSECURE", "True").lower() in (
            "true",
            "1",
            "yes",
        )

        # Validate environment variables and collect missing ones
        missing_vars: list[str] = []
        if not url:
            missing_vars.append("ACI_URL")
        if not username:
            missing_vars.append("ACI_USERNAME")
        if not password:
            missing_vars.append("ACI_PASSWORD")

        if missing_vars:
            raise ValueError(
                f"Missing required environment variables: {', '.join(missing_vars)}"
            )

        # Type narrowing: url, username, password are guaranteed to be str
        # We raised ValueError above if any were None/empty
        assert url is not None
        assert username is not None
        assert password is not None

        # Normalize URL by removing trailing slash
        url = url.rstrip("/")
        verify_ssl = not insecure  # APIC_INSECURE=True means verify=False

        return cls.get_token(url, username, password, verify_ssl)
