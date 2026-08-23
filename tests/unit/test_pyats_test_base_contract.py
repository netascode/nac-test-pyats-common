# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Shared contract tests across architecture-specific TestBase classes.

Each of APICTestBase, SDWANManagerTestBase, and CatalystCenterTestBase guards
its setup() with an identical controller_type mismatch check. This module
covers that behavior once for all three, instead of duplicating it per
architecture test module.
"""

from collections.abc import Callable
from unittest.mock import patch

import pytest
from pyats import aetest  # type: ignore[import-untyped]
from pyats.aetest.signals import AEtestFailedSignal

from nac_test_pyats_common.aci.test_base import APICTestBase
from nac_test_pyats_common.catc.api_test_base import CatalystCenterTestBase
from nac_test_pyats_common.sdwan.api_test_base import SDWANManagerTestBase


@pytest.mark.parametrize(
    ("test_base_cls", "expected_controller_type", "env", "resolved_controller_type"),
    [
        (
            APICTestBase,
            "ACI",
            {
                "SDWAN_URL": "https://sdwan.example.com",
                "SDWAN_USERNAME": "admin",
                "SDWAN_PASSWORD": "password",
            },
            "SDWAN",
        ),
        (
            SDWANManagerTestBase,
            "SDWAN",
            {
                "ACI_URL": "https://apic.example.com",
                "ACI_USERNAME": "admin",
                "ACI_PASSWORD": "password",
            },
            "ACI",
        ),
        (
            CatalystCenterTestBase,
            "CC",
            {
                "ACI_URL": "https://apic.example.com",
                "ACI_USERNAME": "admin",
                "ACI_PASSWORD": "password",
            },
            "ACI",
        ),
    ],
    ids=["aci", "sdwan", "catc"],
)
def test_setup_fails_on_controller_type_mismatch(
    test_base_cls: type[aetest.Testcase],
    expected_controller_type: str,
    env: dict[str, str],
    resolved_controller_type: str,
    make_pyats_instance: Callable[[type], aetest.Testcase],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """setup() fails when nac-test resolved a different controller_type."""
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    test_instance = make_pyats_instance(test_base_cls)

    with patch.object(test_instance, "load_data_model", return_value={"test": "data"}):
        with pytest.raises(AEtestFailedSignal) as exc_info:
            test_instance.setup()

    assert f"controller_type={expected_controller_type}" in str(exc_info.value)
    assert resolved_controller_type in str(exc_info.value)
