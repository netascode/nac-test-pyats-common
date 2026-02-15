# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for APICAuth.

This module tests actual business logic for APIC authentication:
1. Error propagation from subprocess execution
2. Environment variable validation (missing credentials)
3. URL normalization (trailing slash handling)
4. SSL/insecure flag handling

NOTE: The following tests were removed as they only verified mocks return mocked values:
- test_successful_authentication (mock_exec.return_value = {"token": "x"} ->
  assert token == "x")
- test_authentication_with_ssl_verification (same pattern)
- test_authentication_passes_auth_script (only checks mock was called)
- test_credentials_sent_correctly (only checks mock was called with args)
- test_default_verify_ssl_is_false (only checks mock was called with args)
- test_get_token_success (mock returns mock)
- test_auth_func_wrapper_calls_authenticate (mock setup, verify mock called)
- test_get_token_passes_verify_ssl_to_auth_func (mock verification)
- TestConstants class (tests that 600 == 600)
"""

from unittest.mock import MagicMock, patch

import pytest

from nac_test_pyats_common.aci.auth import APICAuth


class TestAuthenticateErrorHandling:
    """Test error handling in authenticate method - actual business logic."""

    @patch("nac_test_pyats_common.aci.auth.execute_auth_subprocess")
    def test_exception_from_subprocess_propagates(self, mock_exec: MagicMock) -> None:
        """Test that exceptions from execute_auth_subprocess propagate correctly.

        This tests the error propagation behavior - when the subprocess execution
        fails, the error should bubble up to the caller. We use RuntimeError as
        a stand-in since the actual SubprocessAuthError inherits from RuntimeError.
        """
        error_msg = "Authentication subprocess failed"
        mock_exec.side_effect = RuntimeError(error_msg)

        with pytest.raises(RuntimeError) as exc_info:
            APICAuth.authenticate(
                "https://apic.example.com", "admin", "wrong-password", verify_ssl=False
            )

        assert error_msg in str(exc_info.value)


class TestGetAuthEnvironmentValidation:
    """Test environment variable validation - actual business logic."""

    def test_get_auth_missing_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test error when APIC_URL is missing."""
        monkeypatch.setenv("APIC_USERNAME", "admin")
        monkeypatch.setenv("APIC_PASSWORD", "password123")
        # APIC_URL not set

        with pytest.raises(ValueError) as exc_info:
            APICAuth.get_auth()

        assert "APIC_URL" in str(exc_info.value)
        assert "Missing required environment variables" in str(exc_info.value)

    def test_get_auth_missing_username(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test error when APIC_USERNAME is missing."""
        monkeypatch.setenv("APIC_URL", "https://apic.example.com")
        monkeypatch.setenv("APIC_PASSWORD", "password123")
        # APIC_USERNAME not set

        with pytest.raises(ValueError) as exc_info:
            APICAuth.get_auth()

        assert "APIC_USERNAME" in str(exc_info.value)

    def test_get_auth_missing_password(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test error when APIC_PASSWORD is missing."""
        monkeypatch.setenv("APIC_URL", "https://apic.example.com")
        monkeypatch.setenv("APIC_USERNAME", "admin")
        # APIC_PASSWORD not set

        with pytest.raises(ValueError) as exc_info:
            APICAuth.get_auth()

        assert "APIC_PASSWORD" in str(exc_info.value)

    def test_get_auth_multiple_missing_vars(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test error message includes all missing variables."""
        # No environment variables set

        with pytest.raises(ValueError) as exc_info:
            APICAuth.get_auth()

        error_msg = str(exc_info.value)
        assert "APIC_URL" in error_msg
        assert "APIC_USERNAME" in error_msg
        assert "APIC_PASSWORD" in error_msg


class TestGetAuthUrlNormalization:
    """Test URL normalization behavior."""

    @patch("nac_test_pyats_common.aci.auth.APICAuth.get_token")
    def test_get_auth_strips_trailing_slash(
        self, mock_get_token: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that trailing slash is removed from URL."""
        monkeypatch.setenv("APIC_URL", "https://apic.example.com/")
        monkeypatch.setenv("APIC_USERNAME", "admin")
        monkeypatch.setenv("APIC_PASSWORD", "password123")

        mock_get_token.return_value = "test-token"

        APICAuth.get_auth()

        # Verify URL was normalized
        call_args = mock_get_token.call_args
        assert call_args[0][0] == "https://apic.example.com"


class TestGetAuthInsecureFlag:
    """Test APIC_INSECURE environment variable handling."""

    @patch("nac_test_pyats_common.aci.auth.APICAuth.get_token")
    def test_get_auth_insecure_default_true(
        self, mock_get_token: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that APIC_INSECURE defaults to True (verify_ssl=False)."""
        monkeypatch.setenv("APIC_URL", "https://apic.example.com")
        monkeypatch.setenv("APIC_USERNAME", "admin")
        monkeypatch.setenv("APIC_PASSWORD", "password123")
        # APIC_INSECURE not set - should default to True

        mock_get_token.return_value = "test-token"

        APICAuth.get_auth()

        # Verify verify_ssl=False was passed (because INSECURE defaults to True)
        call_args = mock_get_token.call_args
        assert call_args[0][3] is False  # verify_ssl parameter

    @patch("nac_test_pyats_common.aci.auth.APICAuth.get_token")
    def test_get_auth_insecure_false_enables_ssl(
        self, mock_get_token: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that APIC_INSECURE=False enables SSL verification."""
        monkeypatch.setenv("APIC_URL", "https://apic.example.com")
        monkeypatch.setenv("APIC_USERNAME", "admin")
        monkeypatch.setenv("APIC_PASSWORD", "password123")
        monkeypatch.setenv("APIC_INSECURE", "False")

        mock_get_token.return_value = "test-token"

        APICAuth.get_auth()

        call_args = mock_get_token.call_args
        assert call_args[0][3] is True  # verify_ssl=True when INSECURE=False

    @patch("nac_test_pyats_common.aci.auth.APICAuth.get_token")
    def test_get_auth_insecure_zero_enables_ssl(
        self, mock_get_token: MagicMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that APIC_INSECURE=0 enables SSL verification."""
        monkeypatch.setenv("APIC_URL", "https://apic.example.com")
        monkeypatch.setenv("APIC_USERNAME", "admin")
        monkeypatch.setenv("APIC_PASSWORD", "password123")
        monkeypatch.setenv("APIC_INSECURE", "0")

        mock_get_token.return_value = "test-token"

        APICAuth.get_auth()

        call_args = mock_get_token.call_args
        assert call_args[0][3] is True  # verify_ssl=True when INSECURE=0
