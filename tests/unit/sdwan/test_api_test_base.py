# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for SDWANManagerTestBase header construction.

Tests that get_sdwan_manager_client() builds correct HTTP headers for:
1. Token auth (Bearer + X-XSRF-TOKEN from JWT)
2. Session auth with XSRF token (JSESSIONID cookie + X-XSRF-TOKEN)
3. Session auth without XSRF token (JSESSIONID cookie only, pre-19.2)
4. Unsupported auth_method raises ValueError
"""

from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from nac_test_pyats_common.sdwan.api_test_base import SDWANManagerTestBase


@pytest.fixture
def test_base(mocker: MockerFixture) -> SDWANManagerTestBase:
    """Create a SDWANManagerTestBase instance with mocked internals."""
    instance = SDWANManagerTestBase.__new__(SDWANManagerTestBase)
    instance.controller_url = "https://sdwan.example.com"

    # Mock pool.get_client to capture the headers passed to it
    mock_pool = MagicMock()
    mock_pool.get_client.return_value = MagicMock()
    instance.pool = mock_pool

    # Mock wrap_client_for_tracking to return the base client unchanged
    instance.wrap_client_for_tracking = MagicMock(  # type: ignore[assignment]
        side_effect=lambda client, **kw: client,
    )

    return instance


class TestGetSDWANManagerClientHeaders:
    """Test header construction in get_sdwan_manager_client()."""

    def test_token_auth_headers(self, test_base: SDWANManagerTestBase) -> None:
        """Token auth sets Bearer Authorization and X-XSRF-TOKEN from JWT."""
        test_base.auth_data = {
            "auth_method": "token",
            "api_token": "my-jwt-token",
            "csrf_token": "csrf-from-jwt",
        }

        test_base.get_sdwan_manager_client()

        headers = test_base.pool.get_client.call_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer my-jwt-token"
        assert headers["X-XSRF-TOKEN"] == "csrf-from-jwt"
        assert headers["Content-Type"] == "application/json"
        assert "Cookie" not in headers

    def test_session_auth_headers_with_xsrf(
        self, test_base: SDWANManagerTestBase
    ) -> None:
        """Session auth sets JSESSIONID cookie and X-XSRF-TOKEN."""
        test_base.auth_data = {
            "auth_method": "session",
            "jsessionid": "sess-abc123",
            "xsrf_token": "xsrf-def456",
        }

        test_base.get_sdwan_manager_client()

        headers = test_base.pool.get_client.call_args.kwargs["headers"]
        assert headers["Cookie"] == "JSESSIONID=sess-abc123"
        assert headers["X-XSRF-TOKEN"] == "xsrf-def456"
        assert headers["Content-Type"] == "application/json"
        assert "Authorization" not in headers

    def test_session_auth_headers_without_xsrf(
        self, test_base: SDWANManagerTestBase
    ) -> None:
        """Pre-19.2 session auth: JSESSIONID cookie only, no X-XSRF-TOKEN."""
        test_base.auth_data = {
            "auth_method": "session",
            "jsessionid": "sess-old",
            "xsrf_token": None,
        }

        test_base.get_sdwan_manager_client()

        headers = test_base.pool.get_client.call_args.kwargs["headers"]
        assert headers["Cookie"] == "JSESSIONID=sess-old"
        assert "X-XSRF-TOKEN" not in headers

    def test_unsupported_auth_method_raises(
        self, test_base: SDWANManagerTestBase
    ) -> None:
        """Unknown auth_method raises ValueError."""
        test_base.auth_data = {"auth_method": "kerberos"}

        with pytest.raises(ValueError, match="Unsupported auth_method"):
            test_base.get_sdwan_manager_client()
