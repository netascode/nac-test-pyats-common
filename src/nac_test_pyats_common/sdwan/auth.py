# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""SDWAN Manager authentication implementation for Cisco SD-WAN.

This module provides authentication functionality for Cisco SDWAN Manager (formerly
vManage), which manages the software-defined WAN fabric. Two authentication
methods are supported:

1. **Token auth** (20.18+): JWT-based Bearer authentication using a pre-generated
   API token. The CSRF token is extracted from the JWT payload and must be sent
   as the X-XSRF-TOKEN header alongside the Bearer Authorization header.
2. **Session auth** (all versions): Form-based login with JSESSIONID cookie and
   optional XSRF token for CSRF protection.

The auth method is determined by `get_matched_credential_set()` from nac-test's
controller detection module.

The module implements a multi-tier API design:
1. _authenticate() - Low-level: direct SDWAN Manager session auth
2. _get_token_auth() - Low-level method for JWT-based token authentication
3. _get_session_auth() - Low-level method for session-based authentication
4. get_auth() - High-level method that routes to the appropriate auth method

This design ensures efficient session management by reusing valid sessions and only
re-authenticating when necessary, reducing unnecessary API calls to the SDWAN Manager.

Note on Fork Safety:
    This module uses urllib instead of httpx for synchronous authentication requests.
    httpx is NOT fork-safe on macOS - creating httpx.Client after fork() causes
    silent crashes due to OpenSSL threading issues. urllib uses simpler primitives
    that work correctly after fork().
"""

import base64
import json
import logging
import os
from typing import Any

from nac_test.pyats_core.common.auth_cache import AuthCache
from nac_test.pyats_core.common.subprocess_auth import (
    SubprocessAuthError,  # noqa: F401 - re-exported for callers to catch
    execute_auth_subprocess,
)

try:
    from nac_test.utils.controller import get_matched_credential_set
except ImportError:
    get_matched_credential_set = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# Default session lifetime for SDWAN Manager authentication in seconds
# SDWAN Manager sessions are typically valid for 30 minutes (1800 seconds) by default
SDWAN_MANAGER_SESSION_LIFETIME_SECONDS: int = 1800

# HTTP timeout for XSRF token fetch (shorter than auth timeout since it's optional)
XSRF_TOKEN_FETCH_TIMEOUT_SECONDS: float = 10.0

# HTTP timeout for authentication request
AUTH_REQUEST_TIMEOUT_SECONDS: float = 30.0

# Authentication script body executed in a subprocess via execute_auth_subprocess.
# Extracted as a module-level constant so unit tests can compile and execute it
# directly with mocked urllib, closing the test gap identified in PR #29 review.
#
# Contract:
#   Input:  `params` dict with keys: url, username, password, timeout,
#           xsrf_timeout, verify_ssl
#   Output: `result` dict with either:
#           - {"jsessionid": str, "xsrf_token": str | None}  (success)
#           - {"error": str}                                   (failure)
_AUTH_SCRIPT_BODY: str = """
import http.cookiejar
import ssl
import urllib.parse
import urllib.request

url = params["url"]
username = params["username"]
password = params["password"]
timeout = params["timeout"]
xsrf_timeout = params["xsrf_timeout"]
verify_ssl = params["verify_ssl"]

# Create SSL context
ssl_context = ssl.create_default_context()
if not verify_ssl:
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

auth_body = None

try:
    auth_response = opener.open(auth_request, timeout=timeout)
    auth_body = auth_response.read().decode("utf-8", errors="replace")
except urllib.error.HTTPError as e:
    if e.code == 302:
        # 302 redirect is expected on successful login
        auth_body = ""
    elif e.code in (401, 403):
        # Defensive: SD-WAN Manager currently returns 200+HTML for bad creds,
        # but if Cisco ever fixes the API to return proper HTTP errors, handle
        # them gracefully instead of falling through to the HTML check.
        result = {
            "error": (
                f"Authentication failed - HTTP {e.code}: {e.reason}. "
                "Verify SDWAN_USERNAME and SDWAN_PASSWORD are correct."
            )
        }
    else:
        # Other HTTP errors (500, 502, etc.) - server/network issue, not creds
        error_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        err_snippet = error_body[:200]
        result = {
            "error": (
                f"Authentication request failed - HTTP {e.code}: {e.reason}. "
                f"{err_snippet}"
            ).strip()
        }
except Exception as e:
    # Network-level errors (socket.timeout, URLError, SSLError, OSError, etc.)
    result = {
        "error": f"Authentication request failed - network error: {e}"
    }

if auth_body is not None:
    # SD-WAN Manager returns HTTP 200 with an HTML login page on auth failure
    # (it never returns 401/403). Successful login returns HTTP 200 with an empty body.
    if auth_body and "<html" in auth_body.lower():
        result = {
            "error": (
                "Authentication failed - SD-WAN Manager returned the login page. "
                "Verify SDWAN_USERNAME and SDWAN_PASSWORD are correct."
            )
        }
    else:
        # Extract JSESSIONID from cookies
        jsessionid = None
        for cookie in cookie_jar:
            if cookie.name == "JSESSIONID":
                jsessionid = cookie.value
                break

        if jsessionid is None:
            result = {
                "error": (
                    "No JSESSIONID cookie received - authentication may have failed"
                )
            }
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
                content_type = token_response.headers.get("Content-Type", "")
                if token_response.status == 200 and "text/html" not in content_type:
                    token_body = token_response.read().decode("utf-8").strip()
                    # Defense-in-depth: real XSRF tokens are hex strings, not HTML
                    if token_body and "<html" not in token_body.lower():
                        xsrf_token = token_body
            except Exception:
                pass  # Pre-19.2 versions do not support XSRF tokens

            result = {"jsessionid": jsessionid, "xsrf_token": xsrf_token}
"""


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
        url: str, username: str, password: str, verify_ssl: bool = False
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
            verify_ssl: Whether to verify SSL certificates. Defaults to False to
                handle self-signed certificates commonly used in lab and development
                deployments.

        Returns:
            A tuple containing:
                - auth_dict (dict): Dictionary with 'jsessionid' (str) and 'xsrf_token'
                  (str | None). The xsrf_token is None for pre-19.2 versions.
                - expires_in (int): Session lifetime in seconds (typically 1800).

        Raises:
            SubprocessAuthError: If authentication subprocess fails.
            ValueError: If the authentication response is malformed.
        """
        # Build auth parameters for subprocess
        auth_params = {
            "url": url,
            "username": username,
            "password": password,
            "timeout": AUTH_REQUEST_TIMEOUT_SECONDS,
            "xsrf_timeout": XSRF_TOKEN_FETCH_TIMEOUT_SECONDS,
            "verify_ssl": verify_ssl,
        }

        # Execute authentication in subprocess (fork-safe on macOS)
        auth_result = execute_auth_subprocess(auth_params, _AUTH_SCRIPT_BODY)

        return {
            "jsessionid": auth_result["jsessionid"],
            "xsrf_token": auth_result.get("xsrf_token"),
        }, SDWAN_MANAGER_SESSION_LIFETIME_SECONDS

    @classmethod
    def get_auth(cls) -> dict[str, Any]:
        """Get SDWAN Manager authentication data with automatic caching and renewal.

        This is the primary method that consumers should use to obtain SDWAN Manager
        authentication data. It consults the credential set matched by nac-test's
        detect_controller_type() to determine the authentication mechanism:

        - **Token auth** (auth_method="token"): Uses SDWAN_API_TOKEN directly.
          No session login required. Returns immediately with the bearer token.
          Available on SD-WAN Manager 20.18+.

        - **Session auth** (auth_method="session"): Uses SDWAN_USERNAME/SDWAN_PASSWORD
          to perform form-based login, obtaining a JSESSIONID cookie and optional
          XSRF token. Leverages AuthCache for efficient session reuse.

        The method uses a cache key based on the controller type ("SDWAN_MANAGER")
        and URL to ensure proper session isolation between different SDWAN Manager
        instances.

        Environment Variables Required (session auth):
            SDWAN_URL: Base URL of the SDWAN Manager
            SDWAN_USERNAME: SDWAN Manager username for authentication
            SDWAN_PASSWORD: SDWAN Manager password for authentication
            SDWAN_INSECURE: If "True", "1", or "yes" (default: "True"), SSL certificate
                verification is disabled. Set to "False" to enable SSL verification.

        Environment Variables Required (token auth):
            SDWAN_URL: Base URL of the SDWAN Manager
            SDWAN_API_TOKEN: API token for bearer authentication (20.18+)

        Returns:
            A dictionary containing:
                - auth_method (str): "token" or "session"
                - api_token (str): Bearer token (only when auth_method="token")
                - jsessionid (str): Session cookie (only when auth_method="session")
                - xsrf_token (str | None): XSRF token (only when auth_method="session")

        Raises:
            ValueError: If required environment variables are not set for the
                determined auth method.
            SubprocessAuthError: If session authentication fails due to invalid
                credentials, network issues, connection timeouts, or SDWAN Manager
                server errors.

        Example:
            >>> # Token auth (20.18+)
            >>> os.environ["SDWAN_URL"] = "https://sdwan-manager.example.com"
            >>> os.environ["SDWAN_API_TOKEN"] = "my-api-token"
            >>> auth_data = SDWANManagerAuth.get_auth()
            >>> auth_data["auth_method"]
            'token'
            >>> headers = {"Authorization": f"Bearer {auth_data['api_token']}"}

            >>> # Session auth (legacy)
            >>> os.environ["SDWAN_URL"] = "https://sdwan-manager.example.com"
            >>> os.environ["SDWAN_USERNAME"] = "admin"
            >>> os.environ["SDWAN_PASSWORD"] = "password123"
            >>> auth_data = SDWANManagerAuth.get_auth()
            >>> auth_data["auth_method"]
            'session'
            >>> headers = {"Cookie": f"JSESSIONID={auth_data['jsessionid']}"}
        """
        # Determine auth method from the credential set matched during detection
        if get_matched_credential_set is not None:
            matched = get_matched_credential_set("SDWAN")
            auth_method = matched.auth_method if matched else "session"
        else:
            logger.warning(
                "nac_test.utils.controller.get_matched_credential_set is not "
                "available — falling back to session auth. This usually "
                "indicates a nac-test version mismatch or incomplete installation."
            )
            auth_method = "session"

        if auth_method == "token":
            return cls._get_token_auth()

        return cls._get_session_auth()

    @classmethod
    def _get_token_auth(cls) -> dict[str, Any]:
        """Get token-based authentication data (SD-WAN Manager 20.18+).

        Reads SDWAN_API_TOKEN from the environment and decodes the JWT payload
        to extract the CSRF token. No network call or caching required.

        The JWT payload is expected to contain a 'csrf' field which must be
        sent as the X-XSRF-TOKEN header alongside the Bearer Authorization
        header on API requests.

        Returns:
            Dictionary with auth_method="token", api_token, and csrf_token.

        Raises:
            ValueError: If SDWAN_URL or SDWAN_API_TOKEN is not set, or if the
                token is not a valid JWT or is missing the 'csrf' field.
        """
        url = os.environ.get("SDWAN_URL")
        api_token = os.environ.get("SDWAN_API_TOKEN")

        if not all([url, api_token]):
            missing_vars: list[str] = []
            if not url:
                missing_vars.append("SDWAN_URL")
            if not api_token:
                missing_vars.append("SDWAN_API_TOKEN")
            raise ValueError(
                f"Missing required environment variables: {', '.join(missing_vars)}"
            )

        # Decode JWT payload to extract CSRF token
        parts = api_token.split(".")  # type: ignore[union-attr]
        if len(parts) != 3:  # noqa: PLR2004
            raise ValueError(
                "SDWAN_API_TOKEN is not a valid JWT: expected 3 dot-separated "
                "parts (header.payload.signature), "
                f"got {len(parts)}."
            )
        try:
            payload_b64 = parts[1]
            # Add padding for base64 decoding
            payload_b64 += "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception as e:
            raise ValueError(
                "Failed to decode SDWAN_API_TOKEN: not a valid JWT. "
                "Verify the token format (header.payload.signature)."
            ) from e

        csrf_token = payload.get("csrf", "")
        if not csrf_token:
            raise ValueError(
                "SDWAN_API_TOKEN is missing 'csrf' field in JWT payload. "
                "Verify the token was generated correctly."
            )

        return {
            "auth_method": "token",
            "api_token": api_token,
            "csrf_token": csrf_token,
        }

    @classmethod
    def _get_session_auth(cls) -> dict[str, Any]:
        """Get session-based authentication data (username/password login).

        Performs form-based login to obtain JSESSIONID and optional XSRF token,
        with caching via AuthCache for session reuse.

        Returns:
            Dictionary with auth_method="session", jsessionid, and xsrf_token.

        Raises:
            ValueError: If SDWAN_URL, SDWAN_USERNAME, or SDWAN_PASSWORD is not set.
            SubprocessAuthError: If authentication fails.
        """
        url = os.environ.get("SDWAN_URL")
        username = os.environ.get("SDWAN_USERNAME")
        password = os.environ.get("SDWAN_PASSWORD")
        insecure = os.environ.get("SDWAN_INSECURE", "True").lower() in (
            "true",
            "1",
            "yes",
        )

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

        # SDWAN_INSECURE=True means verify_ssl=False
        verify_ssl = not insecure

        def auth_wrapper() -> tuple[dict[str, Any], int]:
            """Wrapper for authentication that captures closure variables."""
            return cls._authenticate(url, username, password, verify_ssl)  # type: ignore[arg-type]

        # AuthCache.get_or_create returns dict[str, Any], but mypy can't verify this
        # because nac_test lacks py.typed marker.
        session_data: dict[str, Any] = AuthCache.get_or_create(  # type: ignore[no-any-return]
            controller_type="SDWAN_MANAGER",
            url=url,
            auth_func=auth_wrapper,
        )

        return {"auth_method": "session", **session_data}
