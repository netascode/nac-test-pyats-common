# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for SDWANManagerAuth.

Tests SD-WAN Manager authentication:
1. Error propagation from subprocess execution
2. Environment variable validation (missing credentials)
3. URL normalization (trailing slash handling)
"""

from unittest.mock import MagicMock, patch

import pytest

from nac_test_pyats_common.sdwan.auth import SDWANManagerAuth


class TestAuthenticateErrorHandling:
    """Test error handling in _authenticate method."""

    @patch("nac_test_pyats_common.sdwan.auth.execute_auth_subprocess")
    def test_exception_from_subprocess_propagates(self, mock_exec: MagicMock) -> None:
        """Test that exceptions from execute_auth_subprocess propagate correctly.

        This tests the error propagation behavior - when the subprocess execution
        fails, the error should bubble up to the caller. We use RuntimeError as
        a stand-in since the actual SubprocessAuthError inherits from RuntimeError.
        """
        error_msg = "Authentication subprocess failed"
        mock_exec.side_effect = RuntimeError(error_msg)

        with pytest.raises(RuntimeError) as exc_info:
            SDWANManagerAuth._authenticate(
                "https://sdwan.example.com", "admin", "wrong-password", verify_ssl=False
            )

        assert error_msg in str(exc_info.value)


class TestGetAuthEnvironmentValidation:
    """Test environment variable validation."""

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
