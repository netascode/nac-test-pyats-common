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


# ===========================================================================
# 1. Script body logic — happy path
# ===========================================================================


class TestAuthScriptHappyPath:
    """Test successful authentication scenarios in the script body."""

    def test_success_with_jsessionid_and_xsrf_token(
        self, mocker: MockerFixture
    ) -> None:
        """HTTP 200 + empty body + JSESSIONID cookie + valid XSRF token."""
        auth_resp = _make_http_response(body="")
        token_resp = _make_http_response(
            body="aabbccdd1122", content_type="application/json"
        )
        opener = MagicMock()
        opener.open = MagicMock(side_effect=[auth_resp, token_resp])

        cookie = _make_jsessionid_cookie("sess-xyz")
        jar = MagicMock()
        jar.__iter__ = MagicMock(return_value=iter([cookie]))

        result = _exec_script(mocker, _BASE_PARAMS, opener, jar)

        assert result["jsessionid"] == "sess-xyz"
        assert result["xsrf_token"] == "aabbccdd1122"

    def test_success_via_302_redirect(self, mocker: MockerFixture) -> None:
        """HTTP 302 redirect is treated as successful login."""
        import urllib.error

        http_err = urllib.error.HTTPError(
            url="https://sdwan.example.com/j_security_check",
            code=302,
            msg="Found",
            hdrs=MagicMock(),
            fp=BytesIO(b""),
        )
        token_resp = _make_http_response(body="deadbeef", content_type="text/plain")
        opener = MagicMock()
        opener.open = MagicMock(side_effect=[http_err, token_resp])

        cookie = _make_jsessionid_cookie("redir-session")
        jar = MagicMock()
        jar.__iter__ = MagicMock(return_value=iter([cookie]))

        result = _exec_script(mocker, _BASE_PARAMS, opener, jar)

        assert result["jsessionid"] == "redir-session"
        assert result["xsrf_token"] == "deadbeef"

    def test_success_without_xsrf_token_pre_19_2(self, mocker: MockerFixture) -> None:
        """Pre-19.2 SD-WAN Manager: XSRF token endpoint raises exception."""
        auth_resp = _make_http_response(body="")
        opener = MagicMock()
        opener.open = MagicMock(
            side_effect=[auth_resp, ConnectionError("not supported")]
        )

        cookie = _make_jsessionid_cookie("old-session")
        jar = MagicMock()
        jar.__iter__ = MagicMock(return_value=iter([cookie]))

        result = _exec_script(mocker, _BASE_PARAMS, opener, jar)

        assert result["jsessionid"] == "old-session"
        assert result["xsrf_token"] is None


# ===========================================================================
# 2. Script body logic — auth failure scenarios
# ===========================================================================


class TestAuthScriptFailureDetection:
    """Test that the script correctly detects authentication failures."""

    def test_html_login_page_returns_error(self, mocker: MockerFixture) -> None:
        """HTTP 200 + HTML body = auth failure (current SD-WAN behavior)."""
        auth_resp = _make_http_response(body=_HTML_LOGIN_PAGE)
        opener = MagicMock()
        opener.open = MagicMock(return_value=auth_resp)

        result = _exec_script(mocker, _BASE_PARAMS, opener)

        assert "error" in result
        assert "returned the login page" in result["error"]
        assert "SDWAN_USERNAME" in result["error"]

    def test_http_401_returns_credential_error(self, mocker: MockerFixture) -> None:
        """HTTP 401 = defensive handling for future SD-WAN API fix."""
        import urllib.error

        http_err = urllib.error.HTTPError(
            url="https://sdwan.example.com/j_security_check",
            code=401,
            msg="Unauthorized",
            hdrs=MagicMock(),
            fp=BytesIO(b""),
        )
        opener = MagicMock()
        opener.open = MagicMock(side_effect=http_err)

        result = _exec_script(mocker, _BASE_PARAMS, opener)

        assert "error" in result
        assert "HTTP 401" in result["error"]
        assert "SDWAN_USERNAME" in result["error"]

    def test_http_403_returns_credential_error(self, mocker: MockerFixture) -> None:
        """HTTP 403 = defensive handling for future SD-WAN API fix."""
        import urllib.error

        http_err = urllib.error.HTTPError(
            url="https://sdwan.example.com/j_security_check",
            code=403,
            msg="Forbidden",
            hdrs=MagicMock(),
            fp=BytesIO(b""),
        )
        opener = MagicMock()
        opener.open = MagicMock(side_effect=http_err)

        result = _exec_script(mocker, _BASE_PARAMS, opener)

        assert "error" in result
        assert "HTTP 403" in result["error"]
        assert "SDWAN_USERNAME" in result["error"]

    def test_http_500_returns_server_error(self, mocker: MockerFixture) -> None:
        """HTTP 500 = server error, not a credentials issue."""
        import urllib.error

        http_err = urllib.error.HTTPError(
            url="https://sdwan.example.com/j_security_check",
            code=500,
            msg="Internal Server Error",
            hdrs=MagicMock(),
            fp=BytesIO(b"something broke"),
        )
        opener = MagicMock()
        opener.open = MagicMock(side_effect=http_err)

        result = _exec_script(mocker, _BASE_PARAMS, opener)

        assert "error" in result
        assert "HTTP 500" in result["error"]
        # Server errors should NOT suggest checking credentials
        assert "SDWAN_USERNAME" not in result["error"]
        assert "something broke" in result["error"]

    def test_network_error_returns_error(self, mocker: MockerFixture) -> None:
        """Non-HTTP exceptions (socket timeout, OSError) are caught."""
        opener = MagicMock()
        opener.open = MagicMock(side_effect=OSError("Connection refused"))

        result = _exec_script(mocker, _BASE_PARAMS, opener)

        assert "error" in result
        assert "network error" in result["error"]
        assert "Connection refused" in result["error"]

    def test_no_jsessionid_cookie_returns_error(self, mocker: MockerFixture) -> None:
        """HTTP 200 + empty body but no JSESSIONID cookie = failure."""
        auth_resp = _make_http_response(body="")
        opener = MagicMock()
        opener.open = MagicMock(return_value=auth_resp)

        # Empty cookie jar — no JSESSIONID
        jar = MagicMock()
        jar.__iter__ = MagicMock(return_value=iter([]))

        result = _exec_script(mocker, _BASE_PARAMS, opener, jar)

        assert "error" in result
        assert "No JSESSIONID cookie" in result["error"]


# ===========================================================================
# 3. Script body logic — XSRF token defense-in-depth
# ===========================================================================


class TestAuthScriptXsrfTokenValidation:
    """Test XSRF token defense-in-depth checks."""

    def test_xsrf_html_content_type_rejected(self, mocker: MockerFixture) -> None:
        """Token endpoint returning text/html is rejected (not stored)."""
        auth_resp = _make_http_response(body="")
        token_resp = _make_http_response(
            body="<html>login</html>", content_type="text/html"
        )
        opener = MagicMock()
        opener.open = MagicMock(side_effect=[auth_resp, token_resp])

        cookie = _make_jsessionid_cookie()
        jar = MagicMock()
        jar.__iter__ = MagicMock(return_value=iter([cookie]))

        result = _exec_script(mocker, _BASE_PARAMS, opener, jar)

        assert result["jsessionid"] == "abc123"
        assert result["xsrf_token"] is None

    def test_xsrf_html_body_rejected(self, mocker: MockerFixture) -> None:
        """Token body containing '<html' is rejected even with ok content-type."""
        auth_resp = _make_http_response(body="")
        token_resp = _make_http_response(
            body="<HTML><body>Login Page</body></HTML>",
            content_type="application/octet-stream",
        )
        opener = MagicMock()
        opener.open = MagicMock(side_effect=[auth_resp, token_resp])

        cookie = _make_jsessionid_cookie()
        jar = MagicMock()
        jar.__iter__ = MagicMock(return_value=iter([cookie]))

        result = _exec_script(mocker, _BASE_PARAMS, opener, jar)

        assert result["xsrf_token"] is None

    def test_xsrf_empty_body_rejected(self, mocker: MockerFixture) -> None:
        """Empty XSRF token body is treated as None."""
        auth_resp = _make_http_response(body="")
        token_resp = _make_http_response(body="   ", content_type="application/json")
        opener = MagicMock()
        opener.open = MagicMock(side_effect=[auth_resp, token_resp])

        cookie = _make_jsessionid_cookie()
        jar = MagicMock()
        jar.__iter__ = MagicMock(return_value=iter([cookie]))

        result = _exec_script(mocker, _BASE_PARAMS, opener, jar)

        assert result["xsrf_token"] is None
