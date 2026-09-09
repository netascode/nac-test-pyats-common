# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for FTDTestBase.get_ssh_device_inventory().

Tests the classmethod delegation to FTDDeviceResolver and the
_last_resolver pattern used by nac-test to access skipped_devices.
"""

from typing import Any

import pytest

from nac_test_pyats_common.fmc.device_resolver import FTDDeviceResolver
from nac_test_pyats_common.fmc.ssh_test_base import FTDTestBase


@pytest.fixture
def sample_data_model() -> dict[str, Any]:
    """FMC data model with devices across multiple domains."""
    return {
        "fmc": {
            "domains": [
                {
                    "name": "Global",
                    "devices": {
                        "devices": [
                            {"name": "FTD-DC-FW1", "host": "10.1.1.100"},
                            {"name": "FTD-DC-FW2", "host": "10.1.1.101"},
                        ]
                    },
                },
                {
                    "name": "Branch",
                    "devices": {
                        "devices": [
                            {"name": "FTD-BR-FW1", "host": "10.2.1.100"},
                        ]
                    },
                },
            ]
        }
    }


class TestFTDTestBaseGetSSHDeviceInventory:
    """Test get_ssh_device_inventory() classmethod delegation."""

    def test_returns_resolved_devices(
        self, sample_data_model: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Delegation returns devices from FTDDeviceResolver."""
        monkeypatch.setenv("FTD_USERNAME", "admin")
        monkeypatch.setenv("FTD_PASSWORD", "password")

        devices = FTDTestBase.get_ssh_device_inventory(sample_data_model)

        assert len(devices) == 3
        assert devices[0]["hostname"] == "FTD-DC-FW1"
        assert devices[0]["os"] == "fxos"
        assert devices[0]["platform"] == "ftd"

    def test_sets_last_resolver(
        self, sample_data_model: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_last_resolver is set to the FTDDeviceResolver instance."""
        monkeypatch.setenv("FTD_USERNAME", "admin")
        monkeypatch.setenv("FTD_PASSWORD", "password")

        FTDTestBase.get_ssh_device_inventory(sample_data_model)

        assert isinstance(FTDTestBase._last_resolver, FTDDeviceResolver)

    def test_last_resolver_exposes_skipped_devices(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_last_resolver.skipped_devices is accessible after resolution."""
        monkeypatch.setenv("FTD_USERNAME", "admin")
        monkeypatch.setenv("FTD_PASSWORD", "password")

        data_model = {
            "fmc": {
                "domains": [
                    {
                        "name": "Global",
                        "devices": {
                            "devices": [
                                {"name": "FTD-GOOD", "host": "10.1.1.100"},
                                {"host": "10.1.1.200"},  # missing 'name'
                            ]
                        },
                    }
                ]
            }
        }

        devices = FTDTestBase.get_ssh_device_inventory(data_model)

        assert len(devices) == 1
        assert FTDTestBase._last_resolver is not None
        assert len(FTDTestBase._last_resolver.skipped_devices) == 1

    def test_empty_data_model_returns_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Empty data model returns no devices."""
        monkeypatch.setenv("FTD_USERNAME", "admin")
        monkeypatch.setenv("FTD_PASSWORD", "password")

        devices = FTDTestBase.get_ssh_device_inventory({})

        assert devices == []
        assert FTDTestBase._last_resolver is not None
        assert FTDTestBase._last_resolver.skipped_devices == []

    def test_missing_credentials_raises(
        self, sample_data_model: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Missing credentials propagate ValueError from resolver."""
        monkeypatch.delenv("FTD_USERNAME", raising=False)
        monkeypatch.delenv("FTD_PASSWORD", raising=False)

        with pytest.raises(ValueError, match="Missing required credential"):
            FTDTestBase.get_ssh_device_inventory(sample_data_model)
