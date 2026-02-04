# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for CatalystCenterAuth.

Tests Catalyst Center authentication:
1. Error propagation from subprocess execution
2. Environment variable validation (missing credentials)
3. URL normalization (trailing slash handling)
"""

from unittest.mock import MagicMock, patch

import pytest

from nac_test_pyats_common.catc.auth import CatalystCenterAuth


class TestAuthenticateErrorHandling:
    """Test error handling in _authenticate method."""

    @patch("nac_test_pyats_common.catc.auth.execute_auth_subprocess")
    def test_subprocess_error_propagates(self, mock_exec: MagicMock) -> None:
        """Test that subprocess errors propagate correctly."""
        from nac_test.pyats_core.common.subprocess_auth import SubprocessAuthError

        mock_exec.side_effect = SubprocessAuthError(
            "Authentication failed on all endpoints"
        )

        with pytest.raises(SubprocessAuthError) as exc_info:
            CatalystCenterAuth._authenticate(
                "https://catalyst.example.com",
                "admin",
                "wrong-password",
                verify_ssl=False,
            )

        assert "authentication failed" in str(exc_info.value).lower()


class TestGetAuthEnvironmentValidation:
    """Test environment variable validation."""

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


class TestGetAuthUrlNormalization:
    """Test URL normalization behavior."""

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
