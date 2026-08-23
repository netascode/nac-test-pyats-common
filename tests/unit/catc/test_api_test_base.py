# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for CatalystCenterTestBase.setup().

Tests:
1. controller_type match resolves connection_params and obtains a token
2. Auth failures are converted to FAILED (not ERRORED)
3. CC_INSECURE controls verify_ssl

The controller_type mismatch guard is covered once for all architectures in
tests/unit/test_pyats_test_base_contract.py.
"""

from collections.abc import Callable, Iterator
from unittest.mock import patch

import pytest
from pyats.aetest.signals import AEtestFailedSignal

from nac_test_pyats_common.catc.api_test_base import CatalystCenterTestBase


@pytest.fixture
def test_instance(
    make_pyats_instance: Callable[[type], CatalystCenterTestBase],
) -> Iterator[CatalystCenterTestBase]:
    """A CatalystCenterTestBase instance with load_data_model pre-patched."""
    instance = make_pyats_instance(CatalystCenterTestBase)
    with patch.object(instance, "load_data_model", return_value={"test": "data"}):
        yield instance


class TestCatalystCenterTestBaseSetup:
    """Test CatalystCenterTestBase.setup() auth flow."""

    def test_setup_obtains_token_on_controller_type_match(
        self, test_instance: CatalystCenterTestBase, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """setup() resolves connection_params and calls CatalystCenterAuth.get_token()."""  # noqa: E501
        monkeypatch.setenv("CC_URL", "https://cc.example.com/")
        monkeypatch.setenv("CC_USERNAME", "admin")
        monkeypatch.setenv("CC_PASSWORD", "password")
        monkeypatch.setenv("CC_INSECURE", "True")

        with patch(
            "nac_test_pyats_common.catc.api_test_base.CatalystCenterAuth.get_token",
            return_value={"token": "fake-token"},
        ) as mock_get_token:
            test_instance.setup()

        assert test_instance.auth_data == {"token": "fake-token"}
        assert test_instance.controller_url == "https://cc.example.com"
        assert test_instance.verify_ssl is False
        mock_get_token.assert_called_once_with(
            "https://cc.example.com", "admin", "password", False
        )

    def test_setup_respects_cc_insecure_false(
        self, test_instance: CatalystCenterTestBase, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """CC_INSECURE=False enables SSL verification."""
        monkeypatch.setenv("CC_URL", "https://cc.example.com")
        monkeypatch.setenv("CC_USERNAME", "admin")
        monkeypatch.setenv("CC_PASSWORD", "password")
        monkeypatch.setenv("CC_INSECURE", "False")

        with patch(
            "nac_test_pyats_common.catc.api_test_base.CatalystCenterAuth.get_token",
            return_value={"token": "fake-token"},
        ):
            test_instance.setup()

        assert test_instance.verify_ssl is True

    def test_setup_converts_auth_failure_to_failed(
        self, test_instance: CatalystCenterTestBase, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Auth errors are converted to FAILED via self.failed(), not raised."""
        monkeypatch.setenv("CC_URL", "https://cc.example.com")
        monkeypatch.setenv("CC_USERNAME", "admin")
        monkeypatch.setenv("CC_PASSWORD", "password")

        with patch(
            "nac_test_pyats_common.catc.api_test_base.CatalystCenterAuth.get_token",
            side_effect=RuntimeError("boom"),
        ):
            with pytest.raises(AEtestFailedSignal) as exc_info:
                test_instance.setup()

        assert "Authentication failed" in str(exc_info.value)
        assert test_instance.auth_data == {}
