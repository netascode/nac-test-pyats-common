# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

# SPDX-License-Identifier: MPL-2.0

"""FMC (Firepower Management Center) authentication implementation.

This module provides token-based authentication for Cisco FMC's REST API.
FMC uses HTTP Basic Auth to generate an access token, which is then used
for subsequent API calls via the X-auth-access-token header.

Authentication flow:
    1. POST to /api/fmc_platform/v1/auth/generatetoken with Basic Auth
    2. Extract X-auth-access-token and DOMAIN_UUID from response headers
    3. Use access token in subsequent API requests

Note on Fork Safety:
    This module uses urllib (not httpx) for authentication requests.
    httpx is NOT fork-safe on macOS — creating httpx.Client after fork() causes
    silent crashes due to OpenSSL threading issues.
"""

import logging
import os
from typing import Any

from nac_test.pyats_core.common.auth_cache import AuthCache
from nac_test.pyats_core.common.subprocess_auth import (
    SubprocessAuthError,  # noqa: F401 - re-exported for callers to catch
    execute_auth_subprocess,
)

from nac_test_pyats_common.common.env import require_env_vars

logger = logging.getLogger(__name__)

FMC_TOKEN_LIFETIME_SECONDS: int = 1800

AUTH_REQUEST_TIMEOUT_SECONDS: float = 30.0

_AUTH_SCRIPT_BODY: str = """
import base64
import ssl
import urllib.request

url = params["url"]
username = params["username"]
password = params["password"]
timeout = params["timeout"]
verify_ssl = params["verify_ssl"]

# Create SSL context
ssl_context = ssl.create_default_context()
if not verify_ssl:
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

https_handler = urllib.request.HTTPSHandler(context=ssl_context)
opener = urllib.request.build_opener(https_handler)

# Build Basic Auth header
credentials = base64.b64encode(f"{username}:{password}".encode()).decode()

auth_request = urllib.request.Request(
    f"{url}/api/fmc_platform/v1/auth/generatetoken",
    headers={
        "Authorization": f"Basic {credentials}",
        "Content-Length": "0",
    },
    method="POST",
)

try:
    auth_response = opener.open(auth_request, timeout=timeout)
    access_token = auth_response.headers.get("X-auth-access-token")
    domain_uuid = auth_response.headers.get("DOMAIN_UUID")

    if not access_token:
        result = {
            "error": "No X-auth-access-token in response headers. "
            "Verify FMC_USERNAME and FMC_PASSWORD are correct."
        }
    else:
        result = {
            "access_token": access_token,
            "domain_uuid": domain_uuid or "",
        }
except urllib.error.HTTPError as e:
    if e.code in (401, 403):
        result = {
            "error": (
                f"Authentication failed - HTTP {e.code}: {e.reason}. "
                "Verify FMC_USERNAME and FMC_PASSWORD are correct."
            )
        }
    else:
        error_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        err_snippet = error_body[:200]
        result = {
            "error": (
                f"Authentication request failed - HTTP {e.code}: {e.reason}. "
                f"{err_snippet}"
            ).strip()
        }
except Exception as e:
    result = {
        "error": f"Authentication request failed - network error: {e}"
    }
"""


class FMCAuth:
    """FMC authentication implementation.

    Provides token-based authentication for Cisco Firepower Management Center.
    Uses AuthCache for efficient token reuse across parallel test execution.

    Example:
        >>> auth_data = FMCAuth.get_auth()
        >>> headers = {"X-auth-access-token": auth_data["access_token"]}
        >>> domain_uuid = auth_data["domain_uuid"]
    """

    @staticmethod
    def _authenticate(
        url: str, username: str, password: str, verify_ssl: bool = False
    ) -> tuple[dict[str, Any], int]:
        """Perform FMC token generation via subprocess.

        Args:
            url: Base URL of FMC (e.g., "https://fmc.example.com").
            username: FMC username.
            password: FMC password.
            verify_ssl: Whether to verify SSL certificates.

        Returns:
            Tuple of (auth_dict, expires_in_seconds).
            auth_dict contains 'access_token' and 'domain_uuid'.

        Raises:
            SubprocessAuthError: If authentication subprocess fails.
        """
        auth_params = {
            "url": url,
            "username": username,
            "password": password,
            "timeout": AUTH_REQUEST_TIMEOUT_SECONDS,
            "verify_ssl": verify_ssl,
        }

        auth_result = execute_auth_subprocess(auth_params, _AUTH_SCRIPT_BODY)

        return {
            "access_token": auth_result["access_token"],
            "domain_uuid": auth_result.get("domain_uuid", ""),
        }, FMC_TOKEN_LIFETIME_SECONDS

    @classmethod
    def get_auth(cls) -> dict[str, Any]:
        """Get FMC authentication data with automatic caching and renewal.

        Uses AuthCache to avoid redundant token generation across parallel
        test processes.

        Environment Variables Required:
            FMC_URL: Base URL of the FMC
            FMC_USERNAME: FMC username
            FMC_PASSWORD: FMC password
            FMC_INSECURE: If "True"/"1"/"yes", disable SSL verification
                (default: disabled for lab compatibility)

        Returns:
            Dictionary containing:
            - access_token (str): FMC API access token
            - domain_uuid (str): FMC domain UUID for API path construction

        Raises:
            ValueError: If required environment variables are missing.
            SubprocessAuthError: If authentication fails.
        """
        require_env_vars("FMC_URL", "FMC_USERNAME", "FMC_PASSWORD")

        url = os.environ["FMC_URL"].rstrip("/")
        username = os.environ["FMC_USERNAME"]
        password = os.environ["FMC_PASSWORD"]

        insecure_str = os.environ.get("FMC_INSECURE", "True").lower()
        verify_ssl = insecure_str not in ("true", "1", "yes")

        def auth_func() -> tuple[dict[str, Any], int]:
            return cls._authenticate(url, username, password, verify_ssl)

        result: dict[str, Any] = AuthCache.get_or_create(
            controller_type="FMC",
            url=url,
            auth_func=auth_func,
        )
        return result
