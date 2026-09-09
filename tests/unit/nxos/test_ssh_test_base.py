# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for NXOSTestBase.get_ssh_device_inventory()."""

from typing import Any

import pytest

from nac_test_pyats_common.nxos.ssh_test_base import NXOSTestBase


@pytest.fixture
def nxos_data_model() -> dict[str, Any]:
    """Minimal NX-OS data model for ssh_test_base tests."""
    return {
        "nxos": {
            "devices": [
                {"name": "N9K-1", "url": "https://10.1.1.1"},
                {"name": "N9K-2", "url": "https://10.1.1.2"},
            ]
        }
    }


class TestGetSSHDeviceInventory:
    """Test NXOSTestBase.get_ssh_device_inventory() classmethod."""

    def test_returns_resolved_devices(
        self,
        nxos_data_model: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Delegates to NXOSDeviceResolver and returns resolved inventory."""
        monkeypatch.setenv("NXOS_USERNAME", "admin")
        monkeypatch.setenv("NXOS_PASSWORD", "password")

        devices = NXOSTestBase.get_ssh_device_inventory(nxos_data_model)

        assert len(devices) == 2
        assert devices[0]["hostname"] == "N9K-1"
        assert devices[0]["host"] == "10.1.1.1"
        assert devices[0]["os"] == "nxos"
        assert devices[1]["hostname"] == "N9K-2"

    def test_last_resolver_is_set(
        self,
        nxos_data_model: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_last_resolver is populated after calling get_ssh_device_inventory."""
        monkeypatch.setenv("NXOS_USERNAME", "admin")
        monkeypatch.setenv("NXOS_PASSWORD", "password")

        NXOSTestBase.get_ssh_device_inventory(nxos_data_model)

        assert NXOSTestBase._last_resolver is not None

    def test_skipped_devices_accessible_via_last_resolver(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Skipped devices are accessible through _last_resolver after resolution."""
        monkeypatch.setenv("NXOS_USERNAME", "admin")
        monkeypatch.setenv("NXOS_PASSWORD", "password")

        data_model: dict[str, Any] = {
            "nxos": {
                "devices": [
                    {"name": "N9K-GOOD", "url": "https://10.1.1.1"},
                    {"name": "N9K-BAD", "managed": False},
                ]
            }
        }

        devices = NXOSTestBase.get_ssh_device_inventory(data_model)

        assert len(devices) == 1
        assert NXOSTestBase._last_resolver is not None
        assert len(NXOSTestBase._last_resolver.skipped_devices) == 1
        assert NXOSTestBase._last_resolver.skipped_devices[0]["device_id"] == "N9K-BAD"
