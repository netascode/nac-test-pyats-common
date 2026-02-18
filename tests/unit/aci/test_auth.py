# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for APICAuth.

Tests APIC authentication:
1. Error propagation from subprocess execution
2. Environment variable validation (missing credentials)
3. URL normalization (trailing slash handling)
4. SSL/insecure flag handling
"""

from unittest.mock import MagicMock, patch

import pytest

from nac_test_pyats_common.aci.auth import APICAuth


class TestAuthenticateErrorHandling:
    """Test error handling in authenticate method."""

    @patch("nac_test_pyats_common.aci.auth.execute_auth_subprocess")
    def test_subprocess_error_propagates(self, mock_exec: MagicMock) -> None:
        """Test that subprocess errors propagate correctly."""
        from nac_test.pyats_core.common.subprocess_auth import SubprocessAuthError

        mock_exec.side_effect = SubprocessAuthError("Authentication failed")

        with pytest.raises(SubprocessAuthError) as exc_info:
            APICAuth.authenticate(
                "https://apic.example.com", "admin", "wrong-password", verify_ssl=False
            )

        assert "authentication failed" in str(exc_info.value).lower()


class TestGetAuthEnvironmentValidation:
    """Test environment variable validation."""

    def test_get_auth_missing_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test error when ACI_URL is missing."""
        monkeypatch.setenv("ACI_USERNAME", "admin")
        monkeypatch.setenv("ACI_PASSWORD", "password123")
        # ACI_URL not set

        with pytest.raises(ValueError) as exc_info:
            APICAuth.get_auth()

        assert "ACI_URL" in str(exc_info.value)
        assert "Missing required environment variables" in str(exc_info.value)

    def test_get_auth_missing_username(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test error when ACI_USERNAME is missing."""
        monkeypatch.setenv("ACI_URL", "https://apic.example.com")
        monkeypatch.setenv("ACI_PASSWORD", "password123")
        # ACI_USERNAME not set

        with pytest.raises(ValueError) as exc_info:
            APICAuth.get_auth()

        assert "ACI_USERNAME" in str(exc_info.value)

    def test_get_auth_missing_password(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test error when ACI_PASSWORD is missing."""
        monkeypatch.setenv("ACI_URL", "https://apic.example.com")
        monkeypatch.setenv("ACI_USERNAME", "admin")
        # ACI_PASSWORD not set

        with pytest.raises(ValueError) as exc_info:
            APICAuth.get_auth()

        assert "ACI_PASSWORD" in str(exc_info.value)

    def test_get_auth_multiple_missing_vars(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test error message includes all missing variables."""
        # No environment variables set

        with pytest.raises(ValueError) as exc_info:
            APICAuth.get_auth()

        error_msg = str(exc_info.value)
        assert "ACI_URL" in error_msg
        assert "ACI_USERNAME" in error_msg
        assert "ACI_PASSWORD" in error_msg


class TestGetAuthUrlNormalization:
    """Test URL normalization behavior."""

    @patch("nac_test_pyats_common.aci.auth.APICAuth.get_token")
    def test_get_auth_strips_trailing_slash(
        self, mock_get_token: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that trailing slash is removed from URL."""
        monkeypatch.setenv("ACI_URL", "https://apic.example.com/")
        monkeypatch.setenv("ACI_USERNAME", "admin")
        monkeypatch.setenv("ACI_PASSWORD", "password123")

        mock_get_token.return_value = "test-token"

        APICAuth.get_auth()

        # Verify URL was normalized
        call_args = mock_get_token.call_args
        assert call_args[0][0] == "https://apic.example.com"


class TestGetAuthInsecureFlag:
    """Test ACI_INSECURE environment variable handling."""

    @patch("nac_test_pyats_common.aci.auth.APICAuth.get_token")
    def test_get_auth_insecure_default_true(
        self, mock_get_token: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that ACI_INSECURE defaults to True (verify_ssl=False)."""
        monkeypatch.setenv("ACI_URL", "https://apic.example.com")
        monkeypatch.setenv("ACI_USERNAME", "admin")
        monkeypatch.setenv("ACI_PASSWORD", "password123")
        # ACI_INSECURE not set - should default to True

        mock_get_token.return_value = "test-token"

        APICAuth.get_auth()

        # Verify verify_ssl=False was passed (because INSECURE defaults to True)
        call_args = mock_get_token.call_args
        assert call_args[0][3] is False  # verify_ssl parameter

    @patch("nac_test_pyats_common.aci.auth.APICAuth.get_token")
    def test_get_auth_insecure_false_enables_ssl(
        self, mock_get_token: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that ACI_INSECURE=False enables SSL verification."""
        monkeypatch.setenv("ACI_URL", "https://apic.example.com")
        monkeypatch.setenv("ACI_USERNAME", "admin")
        monkeypatch.setenv("ACI_PASSWORD", "password123")
        monkeypatch.setenv("ACI_INSECURE", "False")

        mock_get_token.return_value = "test-token"

        APICAuth.get_auth()

        call_args = mock_get_token.call_args
        assert call_args[0][3] is True  # verify_ssl=True when INSECURE=False

    @patch("nac_test_pyats_common.aci.auth.APICAuth.get_token")
    def test_get_auth_insecure_zero_enables_ssl(
        self, mock_get_token: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that ACI_INSECURE=0 enables SSL verification."""
        monkeypatch.setenv("ACI_URL", "https://apic.example.com")
        monkeypatch.setenv("ACI_USERNAME", "admin")
        monkeypatch.setenv("ACI_PASSWORD", "password123")
        monkeypatch.setenv("ACI_INSECURE", "0")

        mock_get_token.return_value = "test-token"

        APICAuth.get_auth()

        call_args = mock_get_token.call_args
        assert call_args[0][3] is True  # verify_ssl=True when INSECURE=0
