# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

# SPDX-License-Identifier: MPL-2.0

"""Unit tests for FTDDeviceResolver."""

from typing import Any

import pytest

from nac_test_pyats_common.fmc.device_resolver import FTDDeviceResolver


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


@pytest.fixture
def single_domain_data_model() -> dict[str, Any]:
    """FMC data model with a single domain."""
    return {
        "fmc": {
            "domains": [
                {
                    "name": "Global",
                    "devices": {
                        "devices": [
                            {"name": "M1-FPR4215-1", "host": "9.1.29.50"},
                            {"name": "M1-FPR4215-2", "host": "9.1.29.51"},
                        ]
                    },
                }
            ]
        }
    }


@pytest.fixture
def empty_data_model() -> dict[str, Any]:
    """Data model with no FMC data."""
    return {}


class TestFTDDeviceResolverNavigation:
    """Test schema navigation and device flattening."""

    def test_navigate_flattens_across_domains(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Navigate flattens across domains."""
        resolver = FTDDeviceResolver(sample_data_model)
        devices = resolver.navigate_to_devices()
        assert len(devices) == 3
        assert devices[0]["name"] == "FTD-DC-FW1"
        assert devices[1]["name"] == "FTD-DC-FW2"
        assert devices[2]["name"] == "FTD-BR-FW1"

    def test_navigate_single_domain(
        self, single_domain_data_model: dict[str, Any]
    ) -> None:
        """Navigate single domain."""
        resolver = FTDDeviceResolver(single_domain_data_model)
        devices = resolver.navigate_to_devices()
        assert len(devices) == 2

    def test_navigate_missing_fmc_key(self, empty_data_model: dict[str, Any]) -> None:
        """Navigate missing fmc key."""
        resolver = FTDDeviceResolver(empty_data_model)
        devices = resolver.navigate_to_devices()
        assert devices == []

    def test_navigate_empty_domains(self) -> None:
        """Navigate empty domains."""
        resolver = FTDDeviceResolver({"fmc": {"domains": []}})
        devices = resolver.navigate_to_devices()
        assert devices == []

    def test_navigate_domain_missing_devices_key(self) -> None:
        """Navigate domain missing devices key."""
        resolver = FTDDeviceResolver({"fmc": {"domains": [{"name": "Global"}]}})
        devices = resolver.navigate_to_devices()
        assert devices == []

    def test_navigate_domain_empty_device_list(self) -> None:
        """Navigate domain empty device list."""
        resolver = FTDDeviceResolver(
            {"fmc": {"domains": [{"name": "Global", "devices": {"devices": []}}]}}
        )
        devices = resolver.navigate_to_devices()
        assert devices == []


class TestFTDDeviceResolverExtraction:
    """Test field extraction from device data."""

    def test_extract_hostname(self, sample_data_model: dict[str, Any]) -> None:
        """Extract hostname."""
        resolver = FTDDeviceResolver(sample_data_model)
        device = {"name": "FTD-DC-FW1", "host": "10.1.1.100"}
        assert resolver.extract_hostname(device) == "FTD-DC-FW1"

    def test_extract_host_ip(self, sample_data_model: dict[str, Any]) -> None:
        """Extract host ip."""
        resolver = FTDDeviceResolver(sample_data_model)
        device = {"name": "FTD-DC-FW1", "host": "10.1.1.100"}
        assert resolver.extract_host_ip(device) == "10.1.1.100"

    def test_extract_host_ip_missing_raises(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Extract host ip missing raises."""
        resolver = FTDDeviceResolver(sample_data_model)
        device = {"name": "FTD-NO-HOST"}
        with pytest.raises(ValueError, match="no 'host' field"):
            resolver.extract_host_ip(device)

    def test_extract_host_ip_empty_raises(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Extract host ip empty raises."""
        resolver = FTDDeviceResolver(sample_data_model)
        device = {"name": "FTD-EMPTY", "host": ""}
        with pytest.raises(ValueError, match="no 'host' field"):
            resolver.extract_host_ip(device)

    def test_extract_os_platform_type(self, sample_data_model: dict[str, Any]) -> None:
        """Extract os platform type."""
        resolver = FTDDeviceResolver(sample_data_model)
        device = {"name": "FTD-DC-FW1", "host": "10.1.1.100"}
        result = resolver.extract_os_platform_type(device)
        assert result == {"os": "fxos", "platform": "ftd"}

    def test_get_architecture_name(self, sample_data_model: dict[str, Any]) -> None:
        """Get architecture name."""
        resolver = FTDDeviceResolver(sample_data_model)
        assert resolver.get_architecture_name() == "fmc"

    def test_get_schema_root_key(self, sample_data_model: dict[str, Any]) -> None:
        """Get schema root key."""
        resolver = FTDDeviceResolver(sample_data_model)
        assert resolver.get_schema_root_key() == "fmc"

    def test_get_credential_env_vars(self, sample_data_model: dict[str, Any]) -> None:
        """Get credential env vars."""
        resolver = FTDDeviceResolver(sample_data_model)
        assert resolver.get_credential_env_vars() == ("FTD_USERNAME", "FTD_PASSWORD")


class TestFTDDeviceResolverCredentials:
    """Test credential injection."""

    def test_credentials_injected(
        self, single_domain_data_model: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Credentials injected."""
        monkeypatch.setenv("FTD_USERNAME", "admin")
        monkeypatch.setenv("FTD_PASSWORD", "C1sco12345")

        resolver = FTDDeviceResolver(single_domain_data_model)
        devices = resolver.get_resolved_inventory()

        for device in devices:
            assert device["username"] == "%ENV{FTD_USERNAME}"
            assert device["password"] == "%ENV{FTD_PASSWORD}"

    def test_missing_credentials_raises(
        self, single_domain_data_model: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Missing credentials raises."""
        monkeypatch.delenv("FTD_USERNAME", raising=False)
        monkeypatch.delenv("FTD_PASSWORD", raising=False)

        resolver = FTDDeviceResolver(single_domain_data_model)
        with pytest.raises(ValueError, match="Missing required credential"):
            resolver.get_resolved_inventory()


class TestFTDDeviceResolverFullInventory:
    """Test full inventory resolution end-to-end."""

    def test_full_resolution_multi_domain(
        self, sample_data_model: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Full resolution multi domain."""
        monkeypatch.setenv("FTD_USERNAME", "admin")
        monkeypatch.setenv("FTD_PASSWORD", "password")

        resolver = FTDDeviceResolver(sample_data_model)
        devices = resolver.get_resolved_inventory()

        assert len(devices) == 3

        assert devices[0]["hostname"] == "FTD-DC-FW1"
        assert devices[0]["host"] == "10.1.1.100"
        assert devices[0]["os"] == "fxos"
        assert devices[0]["platform"] == "ftd"

        assert devices[1]["hostname"] == "FTD-DC-FW2"
        assert devices[1]["host"] == "10.1.1.101"

        assert devices[2]["hostname"] == "FTD-BR-FW1"
        assert devices[2]["host"] == "10.2.1.100"
