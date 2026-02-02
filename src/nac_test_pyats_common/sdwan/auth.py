# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""SDWAN Manager authentication implementation for Cisco SD-WAN.

This module provides authentication functionality for Cisco SDWAN Manager (formerly
vManage), which manages the software-defined WAN fabric. The authentication mechanism
uses form-based login with JSESSIONID cookie and optional XSRF token for CSRF
protection.

The module implements a two-tier API design:
1. _authenticate() - Low-level method that performs direct SDWAN Manager authentication
2. get_auth() - High-level method that leverages caching for efficient token reuse

This design ensures efficient session management by reusing valid sessions and only
re-authenticating when necessary, reducing unnecessary API calls to the SDWAN Manager.

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

# Default session lifetime for SDWAN Manager authentication in seconds
# SDWAN Manager sessions are typically valid for 30 minutes (1800 seconds) by default
SDWAN_MANAGER_SESSION_LIFETIME_SECONDS: int = 1800

# HTTP timeout for XSRF token fetch (shorter than auth timeout since it's optional)
XSRF_TOKEN_FETCH_TIMEOUT_SECONDS: float = 10.0

# HTTP timeout for authentication request
AUTH_REQUEST_TIMEOUT_SECONDS: float = 30.0


class SDWANManagerAuth:
    """SDWAN Manager authentication implementation with session caching.

    This class provides a two-tier API for SDWAN Manager authentication:

    1. Low-level _authenticate() method: Directly authenticates with SDWAN Manager using
       form-based login and returns session data along with expiration time. This is
       typically used by the caching layer and not called directly by consumers.

    2. High-level get_auth() method: Provides cached session management, automatically
       handling session renewal when expired. This is the primary method that consumers
       should use for obtaining SDWAN Manager authentication data.

    The authentication flow supports both:
    - Pre-19.2 versions: JSESSIONID cookie only
    - 19.2+ versions: JSESSIONID cookie plus X-XSRF-TOKEN header for CSRF protection

    Example:
        >>> # Get authentication data for SDWAN Manager API calls
        >>> auth_data = SDWANManagerAuth.get_auth()
        >>> # Use in requests
        >>> headers = {"Cookie": f"JSESSIONID={auth_data['jsessionid']}"}
        >>> if auth_data.get("xsrf_token"):
        ...     headers["X-XSRF-TOKEN"] = auth_data["xsrf_token"]
    """

    @staticmethod
    def _authenticate(
        url: str, username: str, password: str
    ) -> tuple[dict[str, Any], int]:
        """Perform direct SDWAN Manager authentication and obtain session data.

        This method performs a direct authentication request to the SDWAN Manager
        using form-based login. It returns both the session data and its lifetime
        for proper cache management.

        The authentication process:
        1. POST form credentials to /j_security_check endpoint
        2. Extract JSESSIONID cookie from response
        3. Attempt to fetch XSRF token (for 19.2+ only)
        4. Return session data with TTL

        Note: On macOS, SSL operations in forked processes crash due to OpenSSL
        threading issues. This method uses subprocess with spawn context to perform
        authentication in a fresh process, avoiding the fork+SSL crash.

        Args:
            url: Base URL of the SDWAN Manager (e.g., "https://sdwan-manager.example.com").
                Should not include trailing slashes or API paths.
            username: SDWAN Manager username for authentication. This should be a valid
                user configured with appropriate permissions.
            password: Password for the specified user account.

        Returns:
            A tuple containing:
                - auth_dict (dict): Dictionary with 'jsessionid' (str) and 'xsrf_token'
                  (str | None). The xsrf_token is None for pre-19.2 versions.
                - expires_in (int): Session lifetime in seconds (typically 1800).

        Raises:
            SubprocessAuthError: If authentication subprocess fails.
            ValueError: If the authentication response is malformed.

        Note:
            SSL verification is disabled to handle self-signed certificates commonly
            used in lab and development deployments.
        """
        # Build auth parameters for subprocess
        auth_params = {
            "url": url,
            "username": username,
            "password": password,
            "timeout": AUTH_REQUEST_TIMEOUT_SECONDS,
            "xsrf_timeout": XSRF_TOKEN_FETCH_TIMEOUT_SECONDS,
        }

        # SDWAN-specific authentication logic
        # This script assumes `params` dict is already loaded by execute_auth_subprocess
        auth_script_body = """
import http.cookiejar
import ssl
import urllib.parse
import urllib.request

url = params["url"]
username = params["username"]
password = params["password"]
timeout = params["timeout"]
xsrf_timeout = params["xsrf_timeout"]

# Create SSL context with verification disabled (for lab/dev self-signed certs)
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# Create cookie jar and opener
cookie_jar = http.cookiejar.CookieJar()
https_handler = urllib.request.HTTPSHandler(context=ssl_context)
cookie_handler = urllib.request.HTTPCookieProcessor(cookie_jar)
opener = urllib.request.build_opener(https_handler, cookie_handler)

# Step 1: Form-based login to /j_security_check
auth_data = urllib.parse.urlencode({
    "j_username": username,
    "j_password": password
}).encode("utf-8")

auth_request = urllib.request.Request(
    f"{url}/j_security_check",
    data=auth_data,
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    method="POST"
)

try:
    opener.open(auth_request, timeout=timeout)
except urllib.error.HTTPError as e:
    if e.code != 302:  # 302 redirect is expected on successful login
        raise

# Extract JSESSIONID from cookies
jsessionid = None
for cookie in cookie_jar:
    if cookie.name == "JSESSIONID":
        jsessionid = cookie.value
        break

if jsessionid is None:
    result = {"error": "No JSESSIONID cookie received - authentication may have failed"}
else:
    # Step 2: Fetch XSRF token (required for SDWAN Manager 19.2+)
    xsrf_token = None
    try:
        token_request = urllib.request.Request(
            f"{url}/dataservice/client/token",
            headers={"Cookie": f"JSESSIONID={jsessionid}"},
            method="GET"
        )
        token_response = opener.open(token_request, timeout=xsrf_timeout)
        if token_response.status == 200:
            xsrf_token = token_response.read().decode("utf-8").strip()
    except Exception:
        pass  # Pre-19.2 versions do not support XSRF tokens

    result = {"jsessionid": jsessionid, "xsrf_token": xsrf_token}
"""

        # Execute authentication in subprocess (fork-safe on macOS)
        auth_result = execute_auth_subprocess(auth_params, auth_script_body)

        return {
            "jsessionid": auth_result["jsessionid"],
            "xsrf_token": auth_result.get("xsrf_token"),
        }, SDWAN_MANAGER_SESSION_LIFETIME_SECONDS

    @classmethod
    def get_auth(cls) -> dict[str, Any]:
        """Get SDWAN Manager authentication data with automatic caching and renewal.

        This is the primary method that consumers should use to obtain SDWAN Manager
        authentication data. It leverages the AuthCache to efficiently manage
        session lifecycle, reusing valid sessions and automatically renewing
        expired ones. This significantly reduces the number of authentication
        requests to the SDWAN Manager.

        The method uses a cache key based on the controller type ("SDWAN_MANAGER")
        and URL to ensure proper session isolation between different SDWAN Manager
        instances.

        Environment Variables Required:
            SDWAN_URL: Base URL of the SDWAN Manager
            SDWAN_USERNAME: SDWAN Manager username for authentication
            SDWAN_PASSWORD: SDWAN Manager password for authentication

        Returns:
            A dictionary containing:
                - jsessionid (str): The session cookie value for API requests
                - xsrf_token (str | None): The XSRF token for CSRF protection
                  (None for pre-19.2 versions)

        Raises:
            ValueError: If any required environment variables (SDWAN_URL,
                SDWAN_USERNAME, SDWAN_PASSWORD) are not set.
            httpx.HTTPStatusError: If SDWAN Manager returns a non-2xx status code during
                authentication, typically indicating invalid credentials (401) or
                server issues (5xx).
            httpx.RequestError: If the request fails due to network issues,
                connection timeouts, or other transport-level problems.

        Example:
            >>> # Set environment variables first
            >>> import os
            >>> os.environ["SDWAN_URL"] = "https://sdwan-manager.example.com"
            >>> os.environ["SDWAN_USERNAME"] = "admin"
            >>> os.environ["SDWAN_PASSWORD"] = "password123"
            >>> # Get authentication data
            >>> auth_data = SDWANManagerAuth.get_auth()
            >>> # Use in API requests
            >>> headers = {"Cookie": f"JSESSIONID={auth_data['jsessionid']}"}
            >>> if auth_data.get("xsrf_token"):
            ...     headers["X-XSRF-TOKEN"] = auth_data["xsrf_token"]
        """
        url = os.environ.get("SDWAN_URL")
        username = os.environ.get("SDWAN_USERNAME")
        password = os.environ.get("SDWAN_PASSWORD")

        if not all([url, username, password]):
            missing_vars: list[str] = []
            if not url:
                missing_vars.append("SDWAN_URL")
            if not username:
                missing_vars.append("SDWAN_USERNAME")
            if not password:
                missing_vars.append("SDWAN_PASSWORD")
            raise ValueError(
                f"Missing required environment variables: {', '.join(missing_vars)}"
            )

        # Normalize URL by removing trailing slash
        url = url.rstrip("/")  # type: ignore[union-attr]

        def auth_wrapper() -> tuple[dict[str, Any], int]:
            """Wrapper for authentication that captures closure variables."""
            return cls._authenticate(url, username, password)  # type: ignore[arg-type]

        # AuthCache.get_or_create returns dict[str, Any], but mypy can't verify this
        # because nac_test lacks py.typed marker.
        return AuthCache.get_or_create(  # type: ignore[no-any-return]
            controller_type="SDWAN_MANAGER",
            url=url,
            auth_func=auth_wrapper,
        )
