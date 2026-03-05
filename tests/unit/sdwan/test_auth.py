# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for SDWANManagerAuth.

Tests SD-WAN Manager authentication:
1. Auth script body logic via in-process execution with mocked urllib (happy path)
2. Auth script body logic — failure detection (HTML login page, HTTP errors,
   network errors)
3. XSRF token defense-in-depth
4. _authenticate() method integration with execute_auth_subprocess
5. Environment variable validation (missing credentials)
6. URL normalization (trailing slash handling)
7. Script body survival through _indent_script_body() transform
"""

from io import BytesIO
from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from nac_test_pyats_common.sdwan.auth import (
    _AUTH_SCRIPT_BODY,
    SDWANManagerAuth,
)

# ---------------------------------------------------------------------------
# Shared test params used by script body execution tests
# ---------------------------------------------------------------------------
_BASE_PARAMS: dict[str, Any] = {
    "url": "https://sdwan.example.com",
    "username": "admin",
    "password": "password123",
    "timeout": 30.0,
    "xsrf_timeout": 10.0,
    "verify_ssl": False,
}

# Realistic HTML login page snippet returned by SD-WAN Manager on auth failure
_HTML_LOGIN_PAGE: str = (
    "<html><head><title>SD-WAN Manager</title></head>"
    "<body><form action='/j_security_check'>Login</form></body></html>"
)


def _exec_script(
    mocker: MockerFixture,
    params: dict[str, Any],
    mock_opener: MagicMock,
    mock_cookie_jar: MagicMock | None = None,
) -> dict[str, Any]:
    """Execute _AUTH_SCRIPT_BODY in-process with mocked urllib objects.

    This helper sets up the namespace that execute_auth_subprocess normally
    provides (the ``params`` dict) and patches urllib internals so the script
    runs without network I/O.

    Args:
        mocker: The pytest-mock fixture for patching.
        params: The params dict the script expects.
        mock_opener: A mock for ``urllib.request.build_opener()`` return value.
            The mock's ``.open()`` method is called by the script for both
            ``/j_security_check`` and ``/dataservice/client/token``.
        mock_cookie_jar: Optional mock for the cookie jar. If not provided,
            an empty MagicMock with ``__iter__`` returning no cookies is used.

    Returns:
        The ``result`` dict set by the script body.
    """
    if mock_cookie_jar is None:
        mock_cookie_jar = MagicMock()
        mock_cookie_jar.__iter__ = MagicMock(return_value=iter([]))

    mocker.patch("urllib.request.build_opener", return_value=mock_opener)
    mocker.patch("http.cookiejar.CookieJar", return_value=mock_cookie_jar)

    ns: dict[str, Any] = {"params": params}
    exec(compile(_AUTH_SCRIPT_BODY, "<auth_script>", "exec"), ns)  # noqa: S102

    result: dict[str, Any] = ns["result"]
    return result


def _make_jsessionid_cookie(value: str = "abc123") -> MagicMock:
    """Create a mock cookie with name='JSESSIONID'."""
    cookie = MagicMock()
    cookie.name = "JSESSIONID"
    cookie.value = value
    return cookie


def _make_http_response(
    body: str = "",
    status: int = 200,
    content_type: str = "application/json",
) -> MagicMock:
    """Create a mock HTTP response from ``opener.open()``."""
    resp = MagicMock()
    resp.read.return_value = body.encode("utf-8")
    resp.status = status
    resp.headers = MagicMock()
    resp.headers.get = MagicMock(
        side_effect=lambda key, default="": (
            content_type if key == "Content-Type" else default
        )
    )
    return resp
