# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for CatalystCenterAuth.

This module tests the Catalyst Center authentication functionality including:
- Direct authentication with token retrieval
- Subprocess-based authentication execution
- Environment variable handling
- Error handling for missing credentials
- SSL verification configuration
"""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from nac_test_pyats_common.catc.auth import (
    AUTH_ENDPOINTS,
    AUTH_REQUEST_TIMEOUT_SECONDS,
    CATALYST_CENTER_TOKEN_LIFETIME_SECONDS,
    CatalystCenterAuth,
)


class TestAuthenticateMethod:
    """Test the low-level _authenticate method."""

    @patch("nac_test_pyats_common.catc.auth.execute_auth_subprocess")
    def test_successful_authentication(self, mock_exec: MagicMock) -> None:
        """Test successful authentication."""
        mock_exec.return_value = {"token": "test-token-12345"}

        auth_data, expires_in = CatalystCenterAuth._authenticate(
            "https://catalyst.example.com", "admin", "password123", verify_ssl=False
        )

        assert auth_data["token"] == "test-token-12345"
        assert expires_in == CATALYST_CENTER_TOKEN_LIFETIME_SECONDS

        # Verify execute_auth_subprocess was called with correct params
        mock_exec.assert_called_once()
        call_args = mock_exec.call_args
        auth_params = call_args[0][0]  # First positional arg
        assert auth_params["url"] == "https://catalyst.example.com"
        assert auth_params["username"] == "admin"
        assert auth_params["password"] == "password123"
        assert auth_params["verify_ssl"] is False
        assert auth_params["timeout"] == AUTH_REQUEST_TIMEOUT_SECONDS
        assert auth_params["endpoints"] == AUTH_ENDPOINTS

    @patch("nac_test_pyats_common.catc.auth.execute_auth_subprocess")
    def test_authentication_with_ssl_verification(self, mock_exec: MagicMock) -> None:
        """Test authentication with SSL verification enabled."""
        mock_exec.return_value = {"token": "test-token-ssl"}

        auth_data, expires_in = CatalystCenterAuth._authenticate(
            "https://catalyst.example.com", "admin", "password123", verify_ssl=True
        )

        assert auth_data["token"] == "test-token-ssl"
        assert expires_in == CATALYST_CENTER_TOKEN_LIFETIME_SECONDS

        # Verify verify_ssl=True was passed
        call_args = mock_exec.call_args
        auth_params = call_args[0][0]
        assert auth_params["verify_ssl"] is True

    @patch("nac_test_pyats_common.catc.auth.execute_auth_subprocess")
    def test_authentication_passes_auth_script(self, mock_exec: MagicMock) -> None:
        """Test that authentication script is passed to subprocess."""
        mock_exec.return_value = {"token": "test-token"}

        CatalystCenterAuth._authenticate(
            "https://catalyst.example.com", "admin", "password123", verify_ssl=False
        )

        # Verify auth script was passed as second argument
        call_args = mock_exec.call_args
        auth_script = call_args[0][1]  # Second positional arg
        assert "urllib.request" in auth_script
        assert "Basic Auth" in auth_script or "b64_credentials" in auth_script
        assert "Token" in auth_script  # Extracts Token from response

    @patch("nac_test_pyats_common.catc.auth.execute_auth_subprocess")
    def test_subprocess_error_propagates(self, mock_exec: MagicMock) -> None:
        """Test that subprocess errors propagate correctly."""
        from nac_test.pyats_core.common.subprocess_auth import SubprocessAuthError

        mock_exec.side_effect = SubprocessAuthError("Authentication failed on all endpoints")

        with pytest.raises(SubprocessAuthError) as exc_info:
            CatalystCenterAuth._authenticate(
                "https://catalyst.example.com", "admin", "wrong-password", verify_ssl=False
            )

        assert "authentication failed" in str(exc_info.value).lower()

    @patch("nac_test_pyats_common.catc.auth.execute_auth_subprocess")
    def test_credentials_sent_correctly(self, mock_exec: MagicMock) -> None:
        """Test that credentials are correctly passed to subprocess."""
        mock_exec.return_value = {"token": "test-token"}

        CatalystCenterAuth._authenticate(
            "https://catalyst.example.com", "testuser", "testpass", verify_ssl=False
        )

        # Verify credentials in auth_params
        call_args = mock_exec.call_args
        auth_params = call_args[0][0]
        assert auth_params["username"] == "testuser"
        assert auth_params["password"] == "testpass"


class TestGetAuthMethod:
    """Test the high-level get_auth method with caching."""

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

    @patch("nac_test_pyats_common.catc.auth.execute_auth_subprocess")
    @patch("nac_test_pyats_common.catc.auth.AuthCache.get_or_create")
    def test_auth_func_wrapper_calls_authenticate(
        self, mock_cache: MagicMock, mock_exec: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that auth_func wrapper correctly calls _authenticate."""
        monkeypatch.setenv("CC_URL", "https://catalyst.example.com")
        monkeypatch.setenv("CC_USERNAME", "admin")
        monkeypatch.setenv("CC_PASSWORD", "password123")
        monkeypatch.setenv("CC_INSECURE", "True")

        # Mock the subprocess execution
        mock_exec.return_value = {"token": "direct-token"}

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
