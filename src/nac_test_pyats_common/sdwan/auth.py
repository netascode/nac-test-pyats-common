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

import httpx
from nac_test.pyats_core.common.auth_cache import (
    AuthCache,  # type: ignore[import-untyped]
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
            httpx.HTTPStatusError: If SDWAN Manager returns a non-2xx status code,
                typically indicating authentication failure (401) or server error.
            httpx.RequestError: If the request fails due to network issues,
                connection timeouts, or other transport-level problems.
            ValueError: If the JSESSIONID cookie is not received in the response,
                indicating a malformed or unexpected response.

        Note:
            SSL verification is disabled (verify=False) to handle self-signed
            certificates commonly used in lab and development deployments.
            In production environments, proper certificate validation should be enabled
            by either installing the certificate in the trust store or providing
            a custom CA bundle via the verify parameter.
        """
        # NOTE: SSL verification is disabled (verify=False) to handle self-signed
        # certificates commonly used in lab and development deployments.
        with httpx.Client(verify=False, timeout=AUTH_REQUEST_TIMEOUT_SECONDS) as client:
            # Step 1: Form-based login to SDWAN Manager
            auth_response = client.post(
                f"{url}/j_security_check",
                data={"j_username": username, "j_password": password},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                follow_redirects=False,
            )
            auth_response.raise_for_status()

            # Validate JSESSIONID cookie was received
            if "JSESSIONID" not in auth_response.cookies:
                raise ValueError(
                    "No JSESSIONID cookie received from SDWAN Manager. "
                    "This may indicate invalid credentials or a server error. "
                    f"Response status: {auth_response.status_code}"
                )

            jsessionid = auth_response.cookies["JSESSIONID"]

            # Step 2: Attempt to get XSRF token (19.2+ only)
            # Pre-19.2 versions do not require XSRF token, so failures are expected
            xsrf_token: str | None = None
            try:
                token_response = client.get(
                    f"{url}/dataservice/client/token",
                    cookies={"JSESSIONID": jsessionid},
                    timeout=XSRF_TOKEN_FETCH_TIMEOUT_SECONDS,
                )
                if token_response.status_code == 200:
                    xsrf_token = token_response.text.strip()
            except (httpx.HTTPError, httpx.TimeoutException):
                # Pre-19.2 does not support XSRF tokens, continue without
                pass

            return {
                "jsessionid": jsessionid,
                "xsrf_token": xsrf_token,
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
