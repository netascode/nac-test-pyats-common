# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for SDWANManagerAuth.

This module tests actual business logic for SDWAN Manager authentication:
1. Error propagation from subprocess execution
2. Environment variable validation (missing credentials)
3. URL normalization (trailing slash handling)

NOTE: The following tests were removed as they only verified mocks return mocked values:
- test_successful_authentication (mock_exec.return_value = {...} -> assert auth_data == {...})
- test_authentication_with_ssl_verification (same pattern)
- test_authentication_without_xsrf_token (same pattern)
- test_authentication_passes_auth_script (only checks mock was called)
- test_credentials_sent_correctly (only checks mock was called with args)
- test_default_verify_ssl_is_false (only checks mock was called with args)
- test_get_auth_success (mock returns mock)
- test_get_auth_insecure_default_true (only verifies callable exists)
- test_auth_func_wrapper_calls_authenticate (mock setup, verify mock called)
- test_get_auth_insecure_variations (only checks mock was called)
- TestConstants class (tests that 1800 == 1800, 30.0 == 30.0, 10.0 == 10.0)
"""

from unittest.mock import MagicMock, patch

import pytest

from nac_test_pyats_common.sdwan.auth import SDWANManagerAuth


class TestAuthenticateErrorHandling:
    """Test error handling in _authenticate method - actual business logic."""

    @patch("nac_test_pyats_common.sdwan.auth.execute_auth_subprocess")
    def test_subprocess_error_propagates(self, mock_exec: MagicMock) -> None:
        """Test that subprocess errors propagate correctly."""
        from nac_test.pyats_core.common.subprocess_auth import SubprocessAuthError

        mock_exec.side_effect = SubprocessAuthError("Authentication failed")

        with pytest.raises(SubprocessAuthError) as exc_info:
            SDWANManagerAuth._authenticate(
                "https://sdwan.example.com", "admin", "wrong-password", verify_ssl=False
            )

        assert "authentication failed" in str(exc_info.value).lower()


class TestGetAuthEnvironmentValidation:
    """Test environment variable validation - actual business logic."""

    def test_get_auth_missing_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test error when SDWAN_URL is missing."""
        monkeypatch.setenv("SDWAN_USERNAME", "admin")
        monkeypatch.setenv("SDWAN_PASSWORD", "password123")
        # SDWAN_URL not set

        with pytest.raises(ValueError) as exc_info:
            SDWANManagerAuth.get_auth()

        assert "SDWAN_URL" in str(exc_info.value)
        assert "Missing required environment variables" in str(exc_info.value)

    def test_get_auth_missing_username(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test error when SDWAN_USERNAME is missing."""
        monkeypatch.setenv("SDWAN_URL", "https://sdwan.example.com")
        monkeypatch.setenv("SDWAN_PASSWORD", "password123")
        # SDWAN_USERNAME not set

        with pytest.raises(ValueError) as exc_info:
            SDWANManagerAuth.get_auth()

        assert "SDWAN_USERNAME" in str(exc_info.value)

    def test_get_auth_missing_password(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test error when SDWAN_PASSWORD is missing."""
        monkeypatch.setenv("SDWAN_URL", "https://sdwan.example.com")
        monkeypatch.setenv("SDWAN_USERNAME", "admin")
        # SDWAN_PASSWORD not set

        with pytest.raises(ValueError) as exc_info:
            SDWANManagerAuth.get_auth()

        assert "SDWAN_PASSWORD" in str(exc_info.value)

    def test_get_auth_multiple_missing_vars(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test error message includes all missing variables."""
        # No environment variables set

        with pytest.raises(ValueError) as exc_info:
            SDWANManagerAuth.get_auth()

        error_msg = str(exc_info.value)
        assert "SDWAN_URL" in error_msg
        assert "SDWAN_USERNAME" in error_msg
        assert "SDWAN_PASSWORD" in error_msg


class TestGetAuthUrlNormalization:
    """Test URL normalization behavior."""

    @patch("nac_test_pyats_common.sdwan.auth.AuthCache.get_or_create")
    def test_get_auth_strips_trailing_slash(
        self, mock_cache: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that trailing slash is removed from URL."""
        monkeypatch.setenv("SDWAN_URL", "https://sdwan.example.com/")
        monkeypatch.setenv("SDWAN_USERNAME", "admin")
        monkeypatch.setenv("SDWAN_PASSWORD", "password123")

        mock_cache.return_value = {"jsessionid": "test", "xsrf_token": None}

        SDWANManagerAuth.get_auth()

        # Verify URL was normalized
        call_kwargs = mock_cache.call_args.kwargs
        assert call_kwargs["url"] == "https://sdwan.example.com"
