# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for CatalystCenterDeviceResolver.

This module tests the Catalyst Center device resolver functionality including:
- Schema navigation (catalyst_center.inventory.devices[])
- Device field extraction (name, device_ip, etc.)
- Management IP handling with CIDR stripping
- Credential injection from environment variables
- Error handling for missing fields
- Skipped devices tracking
"""

from typing import Any

import pytest

from nac_test_pyats_common.catc.device_resolver import CatalystCenterDeviceResolver


@pytest.fixture  # type: ignore[untyped-decorator]
def sample_data_model() -> dict[str, Any]:
    """Provide a sample Catalyst Center data model for testing.

    Based on the actual device structure:
        catalyst_center:
          inventory:
            devices:
              - name: P3-BN1
                device_ip: 192.168.38.1
                fqdn_name: P3-BN1.cisco.eu
                pid: C9300-24P
    """
    return {
        "catalyst_center": {
            "inventory": {
                "devices": [
                    {
                        "name": "P3-BN1",
                        "fqdn_name": "P3-BN1.cisco.eu",
                        "device_ip": "192.168.38.1",
                        "pid": "C9300-24P",
                        "state": "ACCESS",
                        "site": "Global/MAX_AREA/MAX_BUILDING",
                    },
                    {
                        "name": "P3-BN2",
                        "device_ip": "192.168.38.2",
                        "fqdn_name": "P3-BN2.cisco.eu",
                        "pid": "C9300-48P",
                    },
                    {
                        "name": "P3-BN3",
                        "device_ip": "10.1.1.100/32",  # Test CIDR stripping
                        "fqdn_name": "P3-BN3.cisco.eu",
                        "pid": "C9500-24Q",
                    },
                ]
            }
        }
    }


@pytest.fixture  # type: ignore[untyped-decorator]
def mock_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set IOSXE credential environment variables."""
    monkeypatch.setenv("IOSXE_USERNAME", "test_user")
    monkeypatch.setenv("IOSXE_PASSWORD", "test_pass")


class TestArchitectureMetadata:
    """Test architecture-specific metadata methods."""

    def test_architecture_name(self, sample_data_model: dict[str, Any]) -> None:
        """Test that architecture name is 'catalyst_center'."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        assert resolver.get_architecture_name() == "catalyst_center"

    def test_schema_root_key(self, sample_data_model: dict[str, Any]) -> None:
        """Test that schema root key is 'catalyst_center'."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        assert resolver.get_schema_root_key() == "catalyst_center"

    def test_credential_env_vars(self, sample_data_model: dict[str, Any]) -> None:
        """Test that credential env vars are IOSXE_USERNAME and IOSXE_PASSWORD."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        username_var, password_var = resolver.get_credential_env_vars()
        assert username_var == "IOSXE_USERNAME"
        assert password_var == "IOSXE_PASSWORD"


class TestSchemaNavigation:
    """Test navigation through Catalyst Center data model."""

    def test_navigate_to_devices(self, sample_data_model: dict[str, Any]) -> None:
        """Test navigation to catalyst_center.inventory.devices[]."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        devices = resolver.navigate_to_devices()

        assert len(devices) == 3
        assert devices[0]["name"] == "P3-BN1"
        assert devices[1]["name"] == "P3-BN2"
        assert devices[2]["name"] == "P3-BN3"

    def test_navigate_with_empty_inventory(self) -> None:
        """Test navigation when inventory is empty."""
        data_model: dict[str, Any] = {"catalyst_center": {"inventory": {"devices": []}}}
        resolver = CatalystCenterDeviceResolver(data_model)
        devices = resolver.navigate_to_devices()

        assert len(devices) == 0

    def test_navigate_with_missing_inventory(self) -> None:
        """Test navigation when inventory key is missing."""
        data_model: dict[str, Any] = {"catalyst_center": {}}
        resolver = CatalystCenterDeviceResolver(data_model)
        devices = resolver.navigate_to_devices()

        assert len(devices) == 0

    def test_navigate_with_missing_catalyst_center(self) -> None:
        """Test navigation when catalyst_center key is missing."""
        data_model: dict[str, Any] = {}
        resolver = CatalystCenterDeviceResolver(data_model)
        devices = resolver.navigate_to_devices()

        assert len(devices) == 0


class TestDeviceValidation:
    """Test device data validation."""

    def test_validate_device_data_rejects_init_state(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Test that devices with INIT state are rejected."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        device_data = {
            "name": "INIT-DEVICE",
            "device_ip": "10.1.1.1",
            "state": "INIT",
        }

        with pytest.raises(ValueError) as exc_info:
            resolver.validate_device_data(device_data)

        assert "unsupported state 'INIT'" in str(exc_info.value)
        assert "not fully provisioned" in str(exc_info.value)

    def test_validate_device_data_rejects_pnp_state(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Test that devices with PNP state are rejected."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        device_data = {
            "name": "PNP-DEVICE",
            "device_ip": "10.1.1.2",
            "state": "PNP",
        }

        with pytest.raises(ValueError) as exc_info:
            resolver.validate_device_data(device_data)

        assert "unsupported state 'PNP'" in str(exc_info.value)

    def test_validate_device_data_case_insensitive(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Test that state check is case-insensitive."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        device_data = {
            "name": "INIT-DEVICE",
            "device_ip": "10.1.1.1",
            "state": "init",  # lowercase
        }

        with pytest.raises(ValueError) as exc_info:
            resolver.validate_device_data(device_data)

        assert "unsupported state 'INIT'" in str(exc_info.value)

    def test_validate_device_data_accepts_valid_states(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Test that devices with valid states pass validation."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)

        # Test various valid states
        for state in ["ACCESS", "BORDER_NODE", "CORE", "DISTRIBUTION", ""]:
            device_data = {
                "name": f"DEVICE-{state}",
                "device_ip": "10.1.1.1",
                "state": state,
            }
            # Should not raise exception
            resolver.validate_device_data(device_data)


class TestDeviceFieldExtraction:
    """Test extraction of device fields."""

    def test_extract_device_id_success(self, sample_data_model: dict[str, Any]) -> None:
        """Test successful device ID extraction from 'name' field."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        device_data = sample_data_model["catalyst_center"]["inventory"]["devices"][0]

        device_id = resolver.extract_device_id(device_data)
        assert device_id == "P3-BN1"

    def test_extract_device_id_missing_name(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Test error when 'name' field is missing."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        device_data = {"device_ip": "10.1.1.1"}

        with pytest.raises(ValueError) as exc_info:
            resolver.extract_device_id(device_data)

        assert "missing 'name' field" in str(exc_info.value).lower()

    def test_extract_hostname_success(self, sample_data_model: dict[str, Any]) -> None:
        """Test successful hostname extraction from 'name' field."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        device_data = sample_data_model["catalyst_center"]["inventory"]["devices"][0]

        hostname = resolver.extract_hostname(device_data)
        assert hostname == "P3-BN1"

    def test_extract_hostname_missing_name(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Test error when 'name' field is missing for hostname."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        device_data = {"device_ip": "10.1.1.1"}

        with pytest.raises(ValueError) as exc_info:
            resolver.extract_hostname(device_data)

        assert "missing 'name' field" in str(exc_info.value).lower()

    def test_extract_os_platform_type(self, sample_data_model: dict[str, Any]) -> None:
        """Test OS and platform info extraction (hardcoded to 'iosxe')."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        device_data = sample_data_model["catalyst_center"]["inventory"]["devices"][0]

        os_platform_info = resolver.extract_os_platform_type(device_data)
        assert isinstance(os_platform_info, dict)
        assert os_platform_info["os"] == "iosxe"


class TestManagementIPExtraction:
    """Test management IP extraction and CIDR stripping."""

    def test_extract_host_ip_success(self, sample_data_model: dict[str, Any]) -> None:
        """Test successful IP extraction from 'device_ip' field."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        device_data = sample_data_model["catalyst_center"]["inventory"]["devices"][0]

        host_ip = resolver.extract_host_ip(device_data)
        assert host_ip == "192.168.38.1"

    def test_extract_host_ip_with_cidr_stripping(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Test IP extraction with CIDR notation stripping."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        device_data = sample_data_model["catalyst_center"]["inventory"]["devices"][2]

        host_ip = resolver.extract_host_ip(device_data)
        assert host_ip == "10.1.1.100"  # /32 stripped

    def test_extract_host_ip_missing_device_ip(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Test error when 'device_ip' field is missing."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        device_data = {"name": "test-device"}

        with pytest.raises(ValueError) as exc_info:
            resolver.extract_host_ip(device_data)

        assert "missing 'device_ip' field" in str(exc_info.value).lower()


class TestCredentialInjection:
    """Test credential injection from environment variables."""

    def test_successful_credential_injection(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test successful injection of credentials from environment variables."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        devices = resolver.get_resolved_inventory()

        for device in devices:
            assert device["username"] == "test_user"
            assert device["password"] == "test_pass"

    def test_error_when_username_env_var_missing(
        self,
        sample_data_model: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test ValueError raised when IOSXE_USERNAME is missing."""
        monkeypatch.setenv("IOSXE_PASSWORD", "test_pass")
        # IOSXE_USERNAME is not set

        resolver = CatalystCenterDeviceResolver(sample_data_model)

        with pytest.raises(ValueError) as exc_info:
            resolver.get_resolved_inventory()

        assert "IOSXE_USERNAME" in str(exc_info.value)

    def test_error_when_password_env_var_missing(
        self,
        sample_data_model: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test ValueError raised when IOSXE_PASSWORD is missing."""
        monkeypatch.setenv("IOSXE_USERNAME", "test_user")
        # IOSXE_PASSWORD is not set

        resolver = CatalystCenterDeviceResolver(sample_data_model)

        with pytest.raises(ValueError) as exc_info:
            resolver.get_resolved_inventory()

        assert "IOSXE_PASSWORD" in str(exc_info.value)


class TestFullResolutionFlow:
    """Test full end-to-end device resolution."""

    def test_full_resolution_success(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test complete device resolution flow."""
        resolver = CatalystCenterDeviceResolver(sample_data_model)
        devices = resolver.get_resolved_inventory()

        assert len(devices) == 3

        # Verify first device
        device1 = devices[0]
        assert device1["hostname"] == "P3-BN1"
        assert device1["host"] == "192.168.38.1"
        assert device1["os"] == "iosxe"
        assert device1["device_id"] == "P3-BN1"
        assert device1["username"] == "test_user"
        assert device1["password"] == "test_pass"

        # Verify device with CIDR stripping
        device3 = devices[2]
        assert device3["host"] == "10.1.1.100"  # CIDR stripped


class TestErrorHandlingAndSkippedDevices:
    """Test error handling and skipped device tracking."""

    def test_skip_device_with_missing_name(
        self,
        mock_credentials: None,
    ) -> None:
        """Test that devices without 'name' are skipped."""
        data_model = {
            "catalyst_center": {
                "inventory": {
                    "devices": [
                        {
                            "name": "P3-BN1",
                            "device_ip": "192.168.38.1",
                        },
                        {
                            # Missing 'name' field
                            "device_ip": "192.168.38.2",
                        },
                        {
                            "name": "P3-BN3",
                            "device_ip": "192.168.38.3",
                        },
                    ]
                }
            }
        }

        resolver = CatalystCenterDeviceResolver(data_model)
        devices = resolver.get_resolved_inventory()

        # Only 2 devices should be successfully resolved
        assert len(devices) == 2
        assert devices[0]["hostname"] == "P3-BN1"
        assert devices[1]["hostname"] == "P3-BN3"

        # Check skipped devices
        assert len(resolver.skipped_devices) == 1
        skipped = resolver.skipped_devices[0]
        assert "device_id" in skipped
        assert "reason" in skipped
        assert "missing 'name' field" in skipped["reason"].lower()

    def test_skip_device_with_missing_device_ip(
        self,
        mock_credentials: None,
    ) -> None:
        """Test that devices without 'device_ip' are skipped."""
        data_model = {
            "catalyst_center": {
                "inventory": {
                    "devices": [
                        {
                            "name": "P3-BN1",
                            "device_ip": "192.168.38.1",
                        },
                        {
                            "name": "P3-BN2",
                            # Missing 'device_ip' field
                        },
                    ]
                }
            }
        }

        resolver = CatalystCenterDeviceResolver(data_model)
        devices = resolver.get_resolved_inventory()

        # Only 1 device should be successfully resolved
        assert len(devices) == 1
        assert devices[0]["hostname"] == "P3-BN1"

        # Check skipped devices
        assert len(resolver.skipped_devices) == 1
        skipped = resolver.skipped_devices[0]
        assert skipped["device_id"] == "P3-BN2"
        assert "missing 'device_ip' field" in skipped["reason"].lower()

    def test_multiple_skipped_devices(
        self,
        mock_credentials: None,
    ) -> None:
        """Test tracking of multiple skipped devices."""
        data_model = {
            "catalyst_center": {
                "inventory": {
                    "devices": [
                        {
                            "name": "P3-BN1",
                            "device_ip": "192.168.38.1",
                        },
                        {
                            # Missing 'name'
                            "device_ip": "192.168.38.2",
                        },
                        {
                            "name": "P3-BN3",
                            # Missing 'device_ip'
                        },
                    ]
                }
            }
        }

        resolver = CatalystCenterDeviceResolver(data_model)
        devices = resolver.get_resolved_inventory()

        # Only 1 device should be successfully resolved
        assert len(devices) == 1
        assert len(resolver.skipped_devices) == 2

    def test_skip_devices_with_init_and_pnp_states(
        self,
        mock_credentials: None,
    ) -> None:
        """Test that devices with INIT and PNP states are skipped during resolution."""
        data_model = {
            "catalyst_center": {
                "inventory": {
                    "devices": [
                        {
                            "name": "P3-BN1",
                            "device_ip": "192.168.38.1",
                            "state": "ACCESS",
                        },
                        {
                            "name": "INIT-DEVICE",
                            "device_ip": "192.168.38.2",
                            "state": "INIT",
                        },
                        {
                            "name": "PNP-DEVICE",
                            "device_ip": "192.168.38.3",
                            "state": "PNP",
                        },
                        {
                            "name": "P3-BN2",
                            "device_ip": "192.168.38.4",
                            "state": "BORDER_NODE",
                        },
                    ]
                }
            }
        }

        resolver = CatalystCenterDeviceResolver(data_model)
        devices = resolver.get_resolved_inventory()

        # Only 2 devices should be resolved (ACCESS and BORDER_NODE)
        assert len(devices) == 2
        assert devices[0]["hostname"] == "P3-BN1"
        assert devices[1]["hostname"] == "P3-BN2"

        # 2 devices should be skipped (INIT and PNP)
        assert len(resolver.skipped_devices) == 2

        # Check INIT device was skipped with correct reason
        init_skipped = [
            d for d in resolver.skipped_devices if "state 'INIT'" in d["reason"]
        ]
        assert len(init_skipped) == 1
        assert "unsupported state 'INIT'" in init_skipped[0]["reason"]
        assert "not fully provisioned" in init_skipped[0]["reason"]

        # Check PNP device was skipped with correct reason
        pnp_skipped = [
            d for d in resolver.skipped_devices if "state 'PNP'" in d["reason"]
        ]
        assert len(pnp_skipped) == 1
        assert "unsupported state 'PNP'" in pnp_skipped[0]["reason"]
