# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Catalyst Center-specific authentication implementation.

This module provides authentication functionality for Cisco Catalyst Center
(formerly DNA Center), which is the central management platform for enterprise
networks. The authentication mechanism uses token-based login with Basic Auth.

The module implements a two-tier API design:
1. _authenticate() - Low-level method that performs direct Catalyst Center
   authentication
2. get_auth() - High-level method that leverages caching for efficient token reuse

This design ensures efficient token management by reusing valid tokens and only
re-authenticating when necessary, reducing unnecessary API calls to the controller.

Note on Fork Safety:
    This module uses urllib instead of httpx for synchronous authentication requests.
    httpx is NOT fork-safe on macOS - creating httpx.Client after fork() causes
    silent crashes due to OpenSSL threading issues. urllib uses simpler primitives
    that work correctly after fork().
"""

import os
from typing import Any

from nac_test.pyats_core.common.auth_cache import AuthCache
from nac_test.pyats_core.common.subprocess_auth import (
    SubprocessAuthError,  # noqa: F401 - re-exported for callers to catch
    execute_auth_subprocess,
)

# Default token lifetime for Catalyst Center authentication in seconds
# Catalyst Center tokens are typically valid for 1 hour (3600 seconds) by default
CATALYST_CENTER_TOKEN_LIFETIME_SECONDS: int = 3600

# HTTP timeout for authentication request
AUTH_REQUEST_TIMEOUT_SECONDS: float = 30.0

# Auth endpoints (try modern first, fallback to legacy)
AUTH_ENDPOINTS: list[str] = [
    "/api/system/v1/auth/token",  # Modern (Catalyst Center 2.x)
    "/dna/system/api/v1/auth/token",  # Legacy (DNA Center 1.x/2.x)
]


class CatalystCenterAuth:
    """Catalyst Center-specific authentication implementation with token caching.

    This class provides a two-tier API for Catalyst Center authentication:

    1. Low-level _authenticate() method: Directly authenticates with Catalyst Center
       using Basic Auth and returns token data along with expiration time. This is
       typically used by the caching layer and not called directly by consumers.

    2. High-level get_auth() method: Provides cached token management, automatically
       handling token renewal when expired. This is the primary method that consumers
       should use for obtaining Catalyst Center tokens.

    The authentication flow supports both:
    - Modern Catalyst Center 2.x: /api/system/v1/auth/token endpoint
    - Legacy DNA Center 1.x/2.x: /dna/system/api/v1/auth/token endpoint

    The class mirrors VManageAuth pattern for consistency across NAC adapters.

    Example:
        >>> # Get authentication data for Catalyst Center API calls
        >>> auth_data = CatalystCenterAuth.get_auth()
        >>> # Use in requests
        >>> headers = {"X-Auth-Token": auth_data["token"]}
    """

    @classmethod
    def _authenticate(
        cls, url: str, username: str, password: str, verify_ssl: bool
    ) -> tuple[dict[str, Any], int]:
        """Perform direct Catalyst Center authentication and obtain token.

        This method performs a direct authentication request to the Catalyst Center
        using Basic Auth. It tries the modern auth endpoint first, then falls back
        to the legacy endpoint if needed for backward compatibility.

        Note: On macOS, SSL operations in forked processes crash due to OpenSSL
        threading issues. This method uses subprocess with spawn context to perform
        authentication in a fresh process, avoiding the fork+SSL crash.

        Args:
            url: Base URL of the Catalyst Center (e.g., "https://catc.example.com").
                Should not include trailing slashes or API paths.
            username: Catalyst Center username for authentication. This should be
                a valid user configured with appropriate permissions.
            password: Password for the specified Catalyst Center user account.
            verify_ssl: Whether to verify SSL certificates. Set to False for
                lab environments with self-signed certificates.

        Returns:
            A tuple containing:
                - auth_dict (dict): Dictionary with 'token' (str) containing the
                  authentication token for API requests.
                - expires_in (int): Token lifetime in seconds (typically 3600).

        Raises:
            SubprocessAuthError: If authentication subprocess fails or authentication
                fails on all available endpoints.
            ValueError: If the authentication response is malformed.

        Note:
            SSL verification can be disabled via the verify_ssl parameter to handle
            self-signed certificates commonly used in lab deployments. In production
            environments, proper certificate validation should be enabled.
        """
        # Build auth parameters for subprocess
        auth_params = {
            "url": url,
            "username": username,
            "password": password,
            "timeout": AUTH_REQUEST_TIMEOUT_SECONDS,
            "verify_ssl": verify_ssl,
            "endpoints": AUTH_ENDPOINTS,
        }

        # Catalyst Center-specific authentication logic
        # This script assumes `params` dict is already loaded by execute_auth_subprocess
        auth_script_body = """
import base64
import json
import ssl
import urllib.request
import urllib.error

url = params["url"]
username = params["username"]
password = params["password"]
timeout = params["timeout"]
verify_ssl = params["verify_ssl"]
endpoints = params["endpoints"]

# Create SSL context
ssl_context = ssl.create_default_context()
if not verify_ssl:
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

# Create Basic Auth header
credentials = f"{username}:{password}"
b64_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
auth_header = f"Basic {b64_credentials}"

# Create HTTPS handler with SSL context
https_handler = urllib.request.HTTPSHandler(context=ssl_context)
opener = urllib.request.build_opener(https_handler)

last_error = None

for endpoint in endpoints:
    try:
        # Create request with Basic Auth and proper headers
        request = urllib.request.Request(
            f"{url}{endpoint}",
            data=None,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": auth_header,
            },
            method="POST"
        )

        # Execute authentication request
        response = opener.open(request, timeout=timeout)
        response_body = response.read().decode("utf-8")
        response_data = json.loads(response_body)

        # Extract token from response
        token = response_data.get("Token")
        if not token:
            raise ValueError(
                f"No 'Token' field in auth response from {endpoint}. "
                f"Response keys: {list(response_data.keys())}"
            )

        result = {"token": str(token)}
        break  # Success - exit loop

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8") if e.fp else ""
        err_snippet = error_body[:200]
        last_error = (
            f"HTTP {e.code} on {endpoint}: {e.reason}. {err_snippet}"
        )
        continue
    except ValueError as e:
        last_error = str(e)
        continue
    except Exception as e:
        last_error = f"{endpoint}: {str(e)}"
        continue
else:
    # Loop completed without break - all endpoints failed
    result = {"error": f"All endpoints failed. Last error: {last_error}"}
"""

        # Execute authentication in subprocess (fork-safe on macOS)
        auth_result = execute_auth_subprocess(auth_params, auth_script_body)

        return {"token": auth_result["token"]}, CATALYST_CENTER_TOKEN_LIFETIME_SECONDS

    @classmethod
    def get_auth(cls) -> dict[str, Any]:
        """Get Catalyst Center authentication data with automatic caching and renewal.

        This is the primary method that consumers should use to obtain Catalyst Center
        tokens. It leverages the AuthCache to efficiently manage token lifecycle,
        reusing valid tokens and automatically renewing expired ones. This significantly
        reduces the number of authentication requests to the Catalyst Center.

        The method uses a cache key based on the controller type ("CC") and URL
        to ensure proper token isolation between different Catalyst Center instances.

        Environment Variables Required:
            CC_URL: Base URL of the Catalyst Center
            CC_USERNAME: Catalyst Center username for authentication
            CC_PASSWORD: Catalyst Center password for authentication
            CC_INSECURE: Optional. Set to "True" to disable SSL verification
                (default: True)

        Returns:
            A dictionary containing:
                - token (str): The authentication token for API requests.
                  Should be included as X-Auth-Token header in subsequent calls.

        Raises:
            ValueError: If any required environment variables (CC_URL, CC_USERNAME,
                CC_PASSWORD) are not set.
            SubprocessAuthError: If authentication fails due to invalid credentials,
                network issues, connection timeouts, or Catalyst Center server errors.
                The error message will contain details from the authentication
                subprocess.

        Example:
            >>> # Set environment variables first
            >>> import os
            >>> os.environ["CC_URL"] = "https://catalyst.example.com"
            >>> os.environ["CC_USERNAME"] = "admin"
            >>> os.environ["CC_PASSWORD"] = "password123"
            >>> os.environ["CC_INSECURE"] = "True"  # For lab environments
            >>> # Get authentication data
            >>> auth_data = CatalystCenterAuth.get_auth()
            >>> # Use in API requests
            >>> headers = {"X-Auth-Token": auth_data["token"]}
        """
        url = os.environ.get("CC_URL")
        username = os.environ.get("CC_USERNAME")
        password = os.environ.get("CC_PASSWORD")
        insecure = os.environ.get("CC_INSECURE", "True").lower() in ("true", "1", "yes")

        if not all([url, username, password]):
            missing_vars: list[str] = []
            if not url:
                missing_vars.append("CC_URL")
            if not username:
                missing_vars.append("CC_USERNAME")
            if not password:
                missing_vars.append("CC_PASSWORD")
            raise ValueError(
                f"Missing required environment variables: {', '.join(missing_vars)}"
            )

        # Normalize URL by removing trailing slash
        url = url.rstrip("/")  # type: ignore[union-attr]
        verify_ssl = not insecure  # CC_INSECURE=True means verify=False

        def auth_wrapper() -> tuple[dict[str, Any], int]:
            """Wrapper for authentication that captures closure variables."""
            return cls._authenticate(url, username, password, verify_ssl)  # type: ignore[arg-type]

        # AuthCache.get_or_create returns dict[str, Any], but mypy can't verify this
        # because nac_test lacks py.typed marker.
        return AuthCache.get_or_create(  # type: ignore[no-any-return]
            controller_type="CC",
            url=url,
            auth_func=auth_wrapper,
        )
