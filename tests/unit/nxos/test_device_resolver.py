# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for NXOSDeviceResolver."""

from typing import Any

import pytest

from nac_test_pyats_common.nxos.device_resolver import NXOSDeviceResolver


@pytest.fixture
def sample_data_model() -> dict[str, Any]:
    """Provide a sample NX-OS data model for testing."""
    return {
        "nxos": {
            "devices": [
                {
                    "name": "N9K-SPINE-1",
                    "url": "https://10.1.1.1",
                },
                {
                    "name": "N9K-LEAF-1",
                    "url": "https://10.1.1.2",
                },
                {
                    "name": "N9K-LEAF-2",
                    "url": "https://10.1.1.3",
                    "managed": True,
                },
            ]
        }
    }


@pytest.fixture
def data_model_with_unmanaged() -> dict[str, Any]:
    """Data model containing a device with managed=false."""
    return {
        "nxos": {
            "devices": [
                {
                    "name": "N9K-ACTIVE",
                    "url": "https://10.1.1.1",
                },
                {
                    "name": "N9K-UNMANAGED",
                    "url": "https://10.1.1.2",
                    "managed": False,
                },
            ]
        }
    }


@pytest.fixture
def empty_data_model() -> dict[str, Any]:
    """Data model with no devices."""
    return {"nxos": {"devices": []}}


class TestNXOSDeviceResolverNavigation:
    """Test schema navigation and device discovery."""

    def test_navigate_to_devices(self, sample_data_model: dict[str, Any]) -> None:
        """Navigate to devices."""
        resolver = NXOSDeviceResolver(sample_data_model)
        devices = resolver.navigate_to_devices()
        assert len(devices) == 3
        assert devices[0]["name"] == "N9K-SPINE-1"
        assert devices[1]["name"] == "N9K-LEAF-1"

    def test_navigate_empty_data_model(self, empty_data_model: dict[str, Any]) -> None:
        """Navigate empty data model."""
        resolver = NXOSDeviceResolver(empty_data_model)
        devices = resolver.navigate_to_devices()
        assert devices == []

    def test_navigate_missing_nxos_key(self) -> None:
        """Navigate missing nxos key."""
        resolver = NXOSDeviceResolver({})
        devices = resolver.navigate_to_devices()
        assert devices == []

    def test_navigate_missing_devices_key(self) -> None:
        """Navigate missing devices key."""
        resolver = NXOSDeviceResolver({"nxos": {}})
        devices = resolver.navigate_to_devices()
        assert devices == []


class TestNXOSDeviceResolverExtraction:
    """Test field extraction from device data."""

    def test_extract_hostname(self, sample_data_model: dict[str, Any]) -> None:
        """Extract hostname."""
        resolver = NXOSDeviceResolver(sample_data_model)
        device = sample_data_model["nxos"]["devices"][0]
        assert resolver.extract_hostname(device) == "N9K-SPINE-1"

    def test_extract_host_ip_https(self, sample_data_model: dict[str, Any]) -> None:
        """Extract host ip https."""
        resolver = NXOSDeviceResolver(sample_data_model)
        device = {"name": "test", "url": "https://10.48.161.104"}
        assert resolver.extract_host_ip(device) == "10.48.161.104"

    def test_extract_host_ip_with_port(self, sample_data_model: dict[str, Any]) -> None:
        """Extract host ip with port."""
        resolver = NXOSDeviceResolver(sample_data_model)
        device = {"name": "test", "url": "https://10.48.161.104:443"}
        assert resolver.extract_host_ip(device) == "10.48.161.104"

    def test_extract_host_ip_http(self, sample_data_model: dict[str, Any]) -> None:
        """Extract host ip http."""
        resolver = NXOSDeviceResolver(sample_data_model)
        device = {"name": "test", "url": "http://192.168.1.1"}
        assert resolver.extract_host_ip(device) == "192.168.1.1"

    def test_extract_host_ip_invalid_url(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Extract host ip invalid url."""
        resolver = NXOSDeviceResolver(sample_data_model)
        device = {"name": "test", "url": "not-a-url"}
        with pytest.raises(ValueError, match="Cannot extract host from URL"):
            resolver.extract_host_ip(device)

    def test_extract_os_platform_type(self, sample_data_model: dict[str, Any]) -> None:
        """Extract os platform type."""
        resolver = NXOSDeviceResolver(sample_data_model)
        device = sample_data_model["nxos"]["devices"][0]
        result = resolver.extract_os_platform_type(device)
        assert result == {"os": "nxos", "platform": "nexus"}

    def test_get_architecture_name(self, sample_data_model: dict[str, Any]) -> None:
        """Get architecture name."""
        resolver = NXOSDeviceResolver(sample_data_model)
        assert resolver.get_architecture_name() == "nxos"

    def test_get_schema_root_key(self, sample_data_model: dict[str, Any]) -> None:
        """Get schema root key."""
        resolver = NXOSDeviceResolver(sample_data_model)
        assert resolver.get_schema_root_key() == "nxos"

    def test_get_credential_env_vars(self, sample_data_model: dict[str, Any]) -> None:
        """Get credential env vars."""
        resolver = NXOSDeviceResolver(sample_data_model)
        assert resolver.get_credential_env_vars() == (
            "NXOS_USERNAME",
            "NXOS_PASSWORD",
        )


class TestNXOSDeviceResolverValidation:
    """Test device validation and filtering."""

    def test_skip_unmanaged_devices(
        self, data_model_with_unmanaged: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Skip unmanaged devices."""
        monkeypatch.setenv("NXOS_USERNAME", "admin")
        monkeypatch.setenv("NXOS_PASSWORD", "password")

        resolver = NXOSDeviceResolver(data_model_with_unmanaged)
        devices = resolver.get_resolved_inventory()

        assert len(devices) == 1
        assert devices[0]["hostname"] == "N9K-ACTIVE"
        assert len(resolver.skipped_devices) == 1
        assert resolver.skipped_devices[0]["device_id"] == "N9K-UNMANAGED"

    def test_managed_true_not_skipped(
        self, sample_data_model: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Managed true not skipped."""
        monkeypatch.setenv("NXOS_USERNAME", "admin")
        monkeypatch.setenv("NXOS_PASSWORD", "password")

        resolver = NXOSDeviceResolver(sample_data_model)
        devices = resolver.get_resolved_inventory()

        assert len(devices) == 3

    def test_managed_absent_not_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Managed absent not skipped."""
        monkeypatch.setenv("NXOS_USERNAME", "admin")
        monkeypatch.setenv("NXOS_PASSWORD", "password")

        data_model = {
            "nxos": {"devices": [{"name": "N9K-1", "url": "https://10.1.1.1"}]}
        }
        resolver = NXOSDeviceResolver(data_model)
        devices = resolver.get_resolved_inventory()
        assert len(devices) == 1

    def test_missing_url_key_skips_device(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Device missing the url key is skipped and tracked."""
        monkeypatch.setenv("NXOS_USERNAME", "admin")
        monkeypatch.setenv("NXOS_PASSWORD", "password")

        data_model: dict[str, Any] = {
            "nxos": {
                "devices": [
                    {"name": "N9K-GOOD", "url": "https://10.1.1.1"},
                    {"name": "N9K-NO-URL"},
                ]
            }
        }
        resolver = NXOSDeviceResolver(data_model)
        devices = resolver.get_resolved_inventory()

        assert len(devices) == 1
        assert devices[0]["hostname"] == "N9K-GOOD"

        assert len(resolver.skipped_devices) == 1
        assert resolver.skipped_devices[0]["device_id"] == "N9K-NO-URL"


class TestNXOSDeviceResolverCredentials:
    """Test credential injection."""

    def test_credentials_injected(
        self, sample_data_model: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Credentials injected."""
        monkeypatch.setenv("NXOS_USERNAME", "admin")
        monkeypatch.setenv("NXOS_PASSWORD", "secret")

        resolver = NXOSDeviceResolver(sample_data_model)
        devices = resolver.get_resolved_inventory()

        for device in devices:
            assert device["username"] == "%ENV{NXOS_USERNAME}"
            assert device["password"] == "%ENV{NXOS_PASSWORD}"

    def test_missing_credentials_raises(
        self, sample_data_model: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Missing credentials raises."""
        monkeypatch.delenv("NXOS_USERNAME", raising=False)
        monkeypatch.delenv("NXOS_PASSWORD", raising=False)

        resolver = NXOSDeviceResolver(sample_data_model)
        with pytest.raises(ValueError, match="Missing required credential"):
            resolver.get_resolved_inventory()


class TestNXOSDeviceResolverFullInventory:
    """Test full inventory resolution end-to-end."""

    def test_full_resolution(
        self, sample_data_model: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Full resolution."""
        monkeypatch.setenv("NXOS_USERNAME", "admin")
        monkeypatch.setenv("NXOS_PASSWORD", "password")

        resolver = NXOSDeviceResolver(sample_data_model)
        devices = resolver.get_resolved_inventory()

        assert len(devices) == 3

        assert devices[0]["hostname"] == "N9K-SPINE-1"
        assert devices[0]["host"] == "10.1.1.1"
        assert devices[0]["os"] == "nxos"
        assert devices[0]["platform"] == "nexus"

        assert devices[1]["hostname"] == "N9K-LEAF-1"
        assert devices[1]["host"] == "10.1.1.2"

        assert devices[2]["hostname"] == "N9K-LEAF-2"
        assert devices[2]["host"] == "10.1.1.3"
