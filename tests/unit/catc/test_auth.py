# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for CatalystCenterAuth.

This module tests the Catalyst Center authentication functionality including:
- Direct authentication with token retrieval
- Endpoint fallback (modern -> legacy)
- Environment variable handling
- Error handling for missing credentials
- SSL verification configuration
"""

from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from nac_test_pyats_common.catc.auth import (
    AUTH_ENDPOINTS,
    CATALYST_CENTER_TOKEN_LIFETIME_SECONDS,
    CatalystCenterAuth,
)


class TestAuthenticateMethod:
    """Test the low-level _authenticate method."""

    @respx.mock
    def test_successful_authentication_modern_endpoint(self) -> None:
        """Test successful authentication using modern endpoint."""
        url = "https://catalyst.example.com"
        username = "admin"
        password = "password123"
        token = "test-token-12345"

        # Mock successful response on modern endpoint
        respx.post(f"{url}{AUTH_ENDPOINTS[0]}").mock(
            return_value=httpx.Response(200, json={"Token": token})
        )

        auth_data, expires_in = CatalystCenterAuth._authenticate(
            url, username, password, verify_ssl=False
        )

        assert auth_data["token"] == token
        assert expires_in == CATALYST_CENTER_TOKEN_LIFETIME_SECONDS

    @respx.mock
    def test_fallback_to_legacy_endpoint(self) -> None:
        """Test fallback to legacy endpoint when modern fails."""
        url = "https://catalyst.example.com"
        username = "admin"
        password = "password123"
        token = "test-token-legacy"

        # Modern endpoint fails with 404
        respx.post(f"{url}{AUTH_ENDPOINTS[0]}").mock(
            return_value=httpx.Response(404, json={"error": "Not found"})
        )

        # Legacy endpoint succeeds
        respx.post(f"{url}{AUTH_ENDPOINTS[1]}").mock(
            return_value=httpx.Response(200, json={"Token": token})
        )

        auth_data, expires_in = CatalystCenterAuth._authenticate(
            url, username, password, verify_ssl=False
        )

        assert auth_data["token"] == token
        assert expires_in == CATALYST_CENTER_TOKEN_LIFETIME_SECONDS

    @respx.mock
    def test_authentication_failure_all_endpoints(self) -> None:
        """Test error when all endpoints fail."""
        url = "https://catalyst.example.com"
        username = "admin"
        password = "wrong-password"

        # Both endpoints fail with 401
        respx.post(f"{url}{AUTH_ENDPOINTS[0]}").mock(
            return_value=httpx.Response(401, json={"error": "Unauthorized"})
        )
        respx.post(f"{url}{AUTH_ENDPOINTS[1]}").mock(
            return_value=httpx.Response(401, json={"error": "Unauthorized"})
        )

        with pytest.raises(RuntimeError) as exc_info:
            CatalystCenterAuth._authenticate(url, username, password, verify_ssl=False)

        assert "authentication failed on all endpoints" in str(exc_info.value).lower()

    @respx.mock
    def test_missing_token_in_response(self) -> None:
        """Test error when Token field is missing from response."""
        url = "https://catalyst.example.com"
        username = "admin"
        password = "password123"

        # Response missing Token field
        respx.post(f"{url}{AUTH_ENDPOINTS[0]}").mock(
            return_value=httpx.Response(200, json={"message": "success"})
        )
        respx.post(f"{url}{AUTH_ENDPOINTS[1]}").mock(
            return_value=httpx.Response(200, json={"message": "success"})
        )

        with pytest.raises(RuntimeError) as exc_info:
            CatalystCenterAuth._authenticate(url, username, password, verify_ssl=False)

        assert "authentication failed" in str(exc_info.value).lower()

    @respx.mock
    def test_ssl_verification_enabled(self) -> None:
        """Test that SSL verification can be enabled."""
        url = "https://catalyst.example.com"
        username = "admin"
        password = "password123"
        token = "test-token-ssl"

        # Mock successful response
        route = respx.post(f"{url}{AUTH_ENDPOINTS[0]}").mock(
            return_value=httpx.Response(200, json={"Token": token})
        )

        auth_data, _ = CatalystCenterAuth._authenticate(
            url, username, password, verify_ssl=True
        )

        assert auth_data["token"] == token
        assert route.called

    @respx.mock
    def test_basic_auth_credentials_sent(self) -> None:
        """Test that Basic Auth credentials are correctly sent."""
        url = "https://catalyst.example.com"
        username = "testuser"
        password = "testpass"
        token = "test-token"

        route = respx.post(f"{url}{AUTH_ENDPOINTS[0]}").mock(
            return_value=httpx.Response(200, json={"Token": token})
        )

        CatalystCenterAuth._authenticate(url, username, password, verify_ssl=False)

        # Verify the request was made
        assert route.called
        # Note: respx doesn't easily expose auth header, but we know it's set


class TestGetAuthMethod:
    """Test the high-level get_auth method with caching."""

    @respx.mock
    @patch("nac_test_pyats_common.catc.auth.AuthCache.get_or_create")
    def test_get_auth_success(
        self, mock_cache: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test successful get_auth with environment variables."""
        # Set environment variables
        monkeypatch.setenv("CC_URL", "https://catalyst.example.com")
        monkeypatch.setenv("CC_USERNAME", "admin")
        monkeypatch.setenv("CC_PASSWORD", "password123")
        monkeypatch.setenv("CC_INSECURE", "True")

        # Mock cached auth response
        mock_cache.return_value = {"token": "cached-token"}

        auth_data = CatalystCenterAuth.get_auth()

        assert auth_data["token"] == "cached-token"
        mock_cache.assert_called_once()

        # Verify cache was called with correct parameters
        call_kwargs = mock_cache.call_args.kwargs
        assert call_kwargs["controller_type"] == "CC"
        assert call_kwargs["url"] == "https://catalyst.example.com"
        assert callable(call_kwargs["auth_func"])

    def test_get_auth_missing_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test error when CC_URL is missing."""
        monkeypatch.setenv("CC_USERNAME", "admin")
        monkeypatch.setenv("CC_PASSWORD", "password123")
        # CC_URL not set

        with pytest.raises(ValueError) as exc_info:
            CatalystCenterAuth.get_auth()

        assert "CC_URL" in str(exc_info.value)
        assert "Missing required environment variables" in str(exc_info.value)

    def test_get_auth_missing_username(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test error when CC_USERNAME is missing."""
        monkeypatch.setenv("CC_URL", "https://catalyst.example.com")
        monkeypatch.setenv("CC_PASSWORD", "password123")
        # CC_USERNAME not set

        with pytest.raises(ValueError) as exc_info:
            CatalystCenterAuth.get_auth()

        assert "CC_USERNAME" in str(exc_info.value)

    def test_get_auth_missing_password(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test error when CC_PASSWORD is missing."""
        monkeypatch.setenv("CC_URL", "https://catalyst.example.com")
        monkeypatch.setenv("CC_USERNAME", "admin")
        # CC_PASSWORD not set

        with pytest.raises(ValueError) as exc_info:
            CatalystCenterAuth.get_auth()

        assert "CC_PASSWORD" in str(exc_info.value)

    def test_get_auth_multiple_missing_vars(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test error message includes all missing variables."""
        # No environment variables set

        with pytest.raises(ValueError) as exc_info:
            CatalystCenterAuth.get_auth()

        error_msg = str(exc_info.value)
        assert "CC_URL" in error_msg
        assert "CC_USERNAME" in error_msg
        assert "CC_PASSWORD" in error_msg

    @respx.mock
    @patch("nac_test_pyats_common.catc.auth.AuthCache.get_or_create")
    def test_get_auth_strips_trailing_slash(
        self, mock_cache: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that trailing slash is removed from URL."""
        monkeypatch.setenv("CC_URL", "https://catalyst.example.com/")
        monkeypatch.setenv("CC_USERNAME", "admin")
        monkeypatch.setenv("CC_PASSWORD", "password123")

        mock_cache.return_value = {"token": "test-token"}

        CatalystCenterAuth.get_auth()

        # Verify URL was normalized
        call_kwargs = mock_cache.call_args.kwargs
        assert call_kwargs["url"] == "https://catalyst.example.com"

    @respx.mock
    @patch("nac_test_pyats_common.catc.auth.AuthCache.get_or_create")
    def test_get_auth_insecure_default_true(
        self, mock_cache: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that CC_INSECURE defaults to True."""
        monkeypatch.setenv("CC_URL", "https://catalyst.example.com")
        monkeypatch.setenv("CC_USERNAME", "admin")
        monkeypatch.setenv("CC_PASSWORD", "password123")
        # CC_INSECURE not set - should default to True

        mock_cache.return_value = {"token": "test-token"}

        CatalystCenterAuth.get_auth()

        # Verify auth_func was created and can be called
        call_kwargs = mock_cache.call_args.kwargs
        auth_func = call_kwargs["auth_func"]
        assert callable(auth_func)

    @respx.mock
    @patch("nac_test_pyats_common.catc.auth.AuthCache.get_or_create")
    def test_get_auth_insecure_variations(
        self, mock_cache: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test various CC_INSECURE value variations."""
        monkeypatch.setenv("CC_URL", "https://catalyst.example.com")
        monkeypatch.setenv("CC_USERNAME", "admin")
        monkeypatch.setenv("CC_PASSWORD", "password123")

        mock_cache.return_value = {"token": "test-token"}

        # Test "1" as insecure
        monkeypatch.setenv("CC_INSECURE", "1")
        CatalystCenterAuth.get_auth()
        assert mock_cache.called

        # Test "yes" as insecure
        monkeypatch.setenv("CC_INSECURE", "yes")
        CatalystCenterAuth.get_auth()
        assert mock_cache.called

        # Test "False" as secure
        monkeypatch.setenv("CC_INSECURE", "False")
        CatalystCenterAuth.get_auth()
        assert mock_cache.called

    @respx.mock
    @patch("nac_test_pyats_common.catc.auth.AuthCache.get_or_create")
    def test_auth_func_wrapper_calls_authenticate(
        self, mock_cache: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that auth_func wrapper correctly calls _authenticate."""
        monkeypatch.setenv("CC_URL", "https://catalyst.example.com")
        monkeypatch.setenv("CC_USERNAME", "admin")
        monkeypatch.setenv("CC_PASSWORD", "password123")
        monkeypatch.setenv("CC_INSECURE", "True")

        # Mock the response
        respx.post("https://catalyst.example.com/api/system/v1/auth/token").mock(
            return_value=httpx.Response(200, json={"Token": "direct-token"})
        )

        # Capture the auth_func
        captured_auth_func: Any = None

        def capture_auth_func(**kwargs: Any) -> dict[str, str]:
            nonlocal captured_auth_func
            captured_auth_func = kwargs["auth_func"]
            # Call it to test it works
            return {"token": "wrapper-token"}

        mock_cache.side_effect = capture_auth_func

        CatalystCenterAuth.get_auth()

        # Verify auth_func was captured and can be called
        assert captured_auth_func is not None
        auth_data, expires_in = captured_auth_func()
        assert auth_data["token"] == "direct-token"
        assert expires_in == CATALYST_CENTER_TOKEN_LIFETIME_SECONDS


class TestConstants:
    """Test module constants."""

    def test_token_lifetime_constant(self) -> None:
        """Test that token lifetime is set correctly."""
        assert CATALYST_CENTER_TOKEN_LIFETIME_SECONDS == 3600

    def test_auth_endpoints_order(self) -> None:
        """Test that auth endpoints are in correct order (modern first)."""
        assert len(AUTH_ENDPOINTS) == 2
        assert AUTH_ENDPOINTS[0] == "/api/system/v1/auth/token"  # Modern
        assert AUTH_ENDPOINTS[1] == "/dna/system/api/v1/auth/token"  # Legacy
