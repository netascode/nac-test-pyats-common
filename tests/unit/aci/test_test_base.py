# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for APICTestBase.setup().

Tests:
1. controller_type match resolves connection_params and obtains a token
2. Auth failures are converted to FAILED (not ERRORED)

The controller_type mismatch guard is covered once for all architectures in
tests/unit/test_pyats_test_base_contract.py.
"""

from collections.abc import Callable, Iterator
from unittest.mock import patch

import pytest
from pyats.aetest.signals import AEtestFailedSignal

from nac_test_pyats_common.aci.test_base import APICTestBase


@pytest.fixture
def test_instance(
    make_pyats_instance: Callable[[type], APICTestBase],
) -> Iterator[APICTestBase]:
    """An APICTestBase instance with load_data_model pre-patched."""
    instance = make_pyats_instance(APICTestBase)
    with patch.object(instance, "load_data_model", return_value={"test": "data"}):
        yield instance


class TestAPICTestBaseSetup:
    """Test APICTestBase.setup() auth flow."""

    def test_setup_obtains_token_on_controller_type_match(
        self, test_instance: APICTestBase, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """setup() resolves connection_params and calls APICAuth.get_token()."""
        monkeypatch.setenv("ACI_URL", "https://apic.example.com")
        monkeypatch.setenv("ACI_USERNAME", "admin")
        monkeypatch.setenv("ACI_PASSWORD", "password")

        with patch(
            "nac_test_pyats_common.aci.test_base.APICAuth.get_token",
            return_value="fake-token",
        ) as mock_get_token:
            test_instance.setup()

        assert test_instance.token == "fake-token"
        mock_get_token.assert_called_once_with(
            "https://apic.example.com", "admin", "password"
        )

    def test_setup_converts_auth_failure_to_failed(
        self, test_instance: APICTestBase, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Auth errors are converted to FAILED via self.failed(), not raised."""
        monkeypatch.setenv("ACI_URL", "https://apic.example.com")
        monkeypatch.setenv("ACI_USERNAME", "admin")
        monkeypatch.setenv("ACI_PASSWORD", "password")

        with patch(
            "nac_test_pyats_common.aci.test_base.APICAuth.get_token",
            side_effect=RuntimeError("boom"),
        ):
            with pytest.raises(AEtestFailedSignal) as exc_info:
                test_instance.setup()

        assert "Authentication failed" in str(exc_info.value)
        assert test_instance.token == ""
