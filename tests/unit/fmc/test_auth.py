# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

# SPDX-License-Identifier: MPL-2.0

"""Unit tests for FMCAuth."""

import ast

import pytest
from pytest_mock import MockerFixture

from nac_test_pyats_common.fmc.auth import (
    _AUTH_SCRIPT_BODY,
    FMC_TOKEN_LIFETIME_SECONDS,
    FMCAuth,
)


class TestAuthScriptBody:
    """Test that the auth script body is valid Python."""

    def test_script_compiles(self) -> None:
        """Auth script body must be syntactically valid Python."""
        ast.parse(_AUTH_SCRIPT_BODY)

    def test_script_uses_params_dict(self) -> None:
        """Auth script body should reference expected params keys."""
        assert "params[" in _AUTH_SCRIPT_BODY
        assert '"url"' in _AUTH_SCRIPT_BODY
        assert '"username"' in _AUTH_SCRIPT_BODY
        assert '"password"' in _AUTH_SCRIPT_BODY

    def test_script_sets_result(self) -> None:
        """Auth script body must set a result dict."""
        assert "result" in _AUTH_SCRIPT_BODY
        assert "access_token" in _AUTH_SCRIPT_BODY
        assert "domain_uuid" in _AUTH_SCRIPT_BODY


class TestFMCAuthAuthenticate:
    """Test the _authenticate static method."""

    def test_authenticate_returns_tuple(self, mocker: MockerFixture) -> None:
        """_authenticate should return (auth_dict, ttl) tuple."""
        mock_subprocess = mocker.patch(
            "nac_test_pyats_common.fmc.auth.execute_auth_subprocess",
            return_value={
                "access_token": "test-token-abc",
                "domain_uuid": "e276abec-e0f2-11e3-8169-6d9ed49b625f",
            },
        )

        auth_data, ttl = FMCAuth._authenticate(
            "https://fmc.example.com", "admin", "password"
        )

        assert auth_data["access_token"] == "test-token-abc"
        assert auth_data["domain_uuid"] == "e276abec-e0f2-11e3-8169-6d9ed49b625f"
        assert ttl == FMC_TOKEN_LIFETIME_SECONDS
        mock_subprocess.assert_called_once()

    def test_authenticate_missing_domain_uuid(self, mocker: MockerFixture) -> None:
        """_authenticate handles missing domain_uuid gracefully."""
        mocker.patch(
            "nac_test_pyats_common.fmc.auth.execute_auth_subprocess",
            return_value={"access_token": "test-token"},
        )

        auth_data, _ = FMCAuth._authenticate(
            "https://fmc.example.com", "admin", "password"
        )

        assert auth_data["access_token"] == "test-token"
        assert auth_data["domain_uuid"] == ""


class TestFMCAuthGetAuth:
    """Test the get_auth class method."""

    def test_get_auth_with_env_vars(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        """get_auth should use env vars and return cached auth data."""
        monkeypatch.setenv("FMC_URL", "https://fmc.lab.local")
        monkeypatch.setenv("FMC_USERNAME", "admin")
        monkeypatch.setenv("FMC_PASSWORD", "C1sco12345")

        expected_data = {
            "access_token": "cached-token",
            "domain_uuid": "domain-123",
        }
        mocker.patch(
            "nac_test_pyats_common.fmc.auth.AuthCache.get_or_create",
            return_value=expected_data,
        )

        result = FMCAuth.get_auth()

        assert result == expected_data

    def test_get_auth_missing_env_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_auth should raise when required env vars are missing."""
        monkeypatch.delenv("FMC_URL", raising=False)
        monkeypatch.delenv("FMC_USERNAME", raising=False)
        monkeypatch.delenv("FMC_PASSWORD", raising=False)

        with pytest.raises(ValueError, match="FMC_URL"):
            FMCAuth.get_auth()

    def test_get_auth_strips_trailing_slash(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        """get_auth should strip trailing slash from FMC_URL."""
        monkeypatch.setenv("FMC_URL", "https://fmc.lab.local/")
        monkeypatch.setenv("FMC_USERNAME", "admin")
        monkeypatch.setenv("FMC_PASSWORD", "pass")

        mock_cache = mocker.patch(
            "nac_test_pyats_common.fmc.auth.AuthCache.get_or_create",
            return_value={"access_token": "t", "domain_uuid": "d"},
        )

        FMCAuth.get_auth()

        call_kwargs = mock_cache.call_args[1]
        assert call_kwargs["url"] == "https://fmc.lab.local"

    def test_get_auth_ssl_verify_default_disabled(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        """By default, FMC_INSECURE=True so verify_ssl=False."""
        monkeypatch.setenv("FMC_URL", "https://fmc.lab.local")
        monkeypatch.setenv("FMC_USERNAME", "admin")
        monkeypatch.setenv("FMC_PASSWORD", "pass")
        monkeypatch.delenv("FMC_INSECURE", raising=False)

        mock_authenticate = mocker.patch.object(
            FMCAuth,
            "_authenticate",
            return_value=({"access_token": "t", "domain_uuid": "d"}, 1800),
        )
        mocker.patch(
            "nac_test_pyats_common.fmc.auth.AuthCache.get_or_create",
            side_effect=lambda controller_type, url, auth_func: auth_func(),
        )

        FMCAuth.get_auth()

        mock_authenticate.assert_called_once_with(
            "https://fmc.lab.local", "admin", "pass", False
        )
