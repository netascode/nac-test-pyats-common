# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for SDWANDeviceResolver.

This module tests the SD-WAN device resolver functionality including:
- Schema navigation (sdwan.sites[].routers[])
- Device field extraction (chassis_id, system_hostname, management IP)
- Management IP resolution (router-level vs global)
- Platform field (should be 'sdwan')
- Credential injection from environment variables
- Error handling for missing fields
- Skipped devices tracking
"""

from typing import Any

import pytest

from nac_test_pyats_common.sdwan.device_resolver import SDWANDeviceResolver


@pytest.fixture  # type: ignore[untyped-decorator]
def sample_data_model() -> dict[str, Any]:
    """Provide a sample SD-WAN data model for testing.

    Based on the actual SD-WAN structure:
        sdwan:
          management_ip_variable: "vpn511_int1_if_ipv4_address"
          sites:
            - name: "site1"
              routers:
                - chassis_id: "ABC123"
                  device_variables:
                    system_hostname: "router1"
                    vpn511_int1_if_ipv4_address: "10.1.1.1/32"
    """
    return {
        "sdwan": {
            "management_ip_variable": "vpn511_int1_if_ipv4_address",
            "sites": [
                {
                    "name": "site1",
                    "routers": [
                        {
                            "chassis_id": "ABC123",
                            "device_variables": {
                                "system_hostname": "router1",
                                "vpn511_int1_if_ipv4_address": "10.1.1.1/32",
                            },
                        },
                        {
                            "chassis_id": "DEF456",
                            "device_variables": {
                                "system_hostname": "router2",
                                "vpn511_int1_if_ipv4_address": "10.1.1.2/32",
                            },
                        },
                    ],
                },
                {
                    "name": "site2",
                    "routers": [
                        {
                            "chassis_id": "GHI789",
                            "device_variables": {
                                "system_hostname": "router3",
                                "vpn511_int1_if_ipv4_address": "10.2.1.1/32",
                            },
                        },
                    ],
                },
            ],
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
        """Test that architecture name is 'sdwan'."""
        resolver = SDWANDeviceResolver(sample_data_model)
        assert resolver.get_architecture_name() == "sdwan"

    def test_schema_root_key(self, sample_data_model: dict[str, Any]) -> None:
        """Test that schema root key is 'sdwan'."""
        resolver = SDWANDeviceResolver(sample_data_model)
        assert resolver.get_schema_root_key() == "sdwan"

    def test_credential_env_vars(self, sample_data_model: dict[str, Any]) -> None:
        """Test that credential env vars are IOSXE_USERNAME and IOSXE_PASSWORD."""
        resolver = SDWANDeviceResolver(sample_data_model)
        username_var, password_var = resolver.get_credential_env_vars()
        assert username_var == "IOSXE_USERNAME"
        assert password_var == "IOSXE_PASSWORD"


class TestSchemaNavigation:
    """Test navigation through SD-WAN data model."""

    def test_navigate_to_devices(self, sample_data_model: dict[str, Any]) -> None:
        """Test navigation to sdwan.sites[].routers[]."""
        resolver = SDWANDeviceResolver(sample_data_model)
        devices = resolver.navigate_to_devices()

        # Should find all routers across all sites
        assert len(devices) == 3
        chassis_ids = [d["chassis_id"] for d in devices]
        assert "ABC123" in chassis_ids
        assert "DEF456" in chassis_ids
        assert "GHI789" in chassis_ids

    def test_navigate_with_empty_sites(self) -> None:
        """Test navigation when sites list is empty."""
        data_model: dict[str, Any] = {
            "sdwan": {
                "management_ip_variable": "vpn511_int1_if_ipv4_address",
                "sites": [],
            }
        }
        resolver = SDWANDeviceResolver(data_model)
        devices = resolver.navigate_to_devices()

        assert len(devices) == 0

    def test_navigate_with_missing_sdwan(self) -> None:
        """Test navigation when sdwan key is missing."""
        data_model: dict[str, Any] = {}
        resolver = SDWANDeviceResolver(data_model)
        devices = resolver.navigate_to_devices()

        assert len(devices) == 0

    def test_navigate_with_sites_missing_routers(self) -> None:
        """Test navigation when sites exist but have no routers."""
        data_model: dict[str, Any] = {
            "sdwan": {
                "management_ip_variable": "vpn511_int1_if_ipv4_address",
                "sites": [{"name": "site1"}],
            }
        }
        resolver = SDWANDeviceResolver(data_model)
        devices = resolver.navigate_to_devices()

        assert len(devices) == 0


class TestDeviceFieldExtraction:
    """Test extraction of device fields."""

    def test_extract_device_id_success(self, sample_data_model: dict[str, Any]) -> None:
        """Test successful device ID extraction from chassis_id."""
        resolver = SDWANDeviceResolver(sample_data_model)
        device_data = sample_data_model["sdwan"]["sites"][0]["routers"][0]

        device_id = resolver.extract_device_id(device_data)
        assert device_id == "ABC123"

    def test_extract_device_id_missing_chassis_id(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Test error when chassis_id is missing."""
        resolver = SDWANDeviceResolver(sample_data_model)
        device_data = {"device_variables": {"system_hostname": "router1"}}

        with pytest.raises(ValueError) as exc_info:
            resolver.extract_device_id(device_data)

        assert "missing 'chassis_id' field" in str(exc_info.value).lower()

    def test_extract_hostname_success(self, sample_data_model: dict[str, Any]) -> None:
        """Test successful hostname extraction from system_hostname."""
        resolver = SDWANDeviceResolver(sample_data_model)
        device_data = sample_data_model["sdwan"]["sites"][0]["routers"][0]

        hostname = resolver.extract_hostname(device_data)
        assert hostname == "router1"

    def test_extract_hostname_fallback_to_chassis_id(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Test hostname fallback to chassis_id when system_hostname is missing."""
        resolver = SDWANDeviceResolver(sample_data_model)
        device_data = {
            "chassis_id": "FALLBACK123",
            "device_variables": {},  # No system_hostname
        }

        hostname = resolver.extract_hostname(device_data)
        assert hostname == "FALLBACK123"

    def test_extract_os_platform_type(self, sample_data_model: dict[str, Any]) -> None:
        """Test OS and platform info extraction."""
        resolver = SDWANDeviceResolver(sample_data_model)
        device_data = sample_data_model["sdwan"]["sites"][0]["routers"][0]

        os_platform_info = resolver.extract_os_platform_type(device_data)
        assert isinstance(os_platform_info, dict)
        assert os_platform_info["os"] == "iosxe"
        assert os_platform_info["platform"] == "sdwan"


class TestManagementIPExtraction:
    """Test management IP extraction and resolution."""

    def test_extract_host_ip_with_global_variable(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Test IP extraction using global management_ip_variable."""
        resolver = SDWANDeviceResolver(sample_data_model)
        device_data = sample_data_model["sdwan"]["sites"][0]["routers"][0]

        host_ip = resolver.extract_host_ip(device_data)
        assert host_ip == "10.1.1.1"  # CIDR /32 stripped

    def test_extract_host_ip_with_router_level_variable(self) -> None:
        """Test IP extraction using router-level management_ip_variable (override)."""
        data_model: dict[str, Any] = {
            "sdwan": {
                "management_ip_variable": "vpn511_int1_if_ipv4_address",
                "sites": [
                    {
                        "name": "site1",
                        "routers": [
                            {
                                "chassis_id": "ABC123",
                                "management_ip_variable": "custom_mgmt_ip",  # Router override
                                "device_variables": {
                                    "system_hostname": "router1",
                                    "vpn511_int1_if_ipv4_address": "10.1.1.1/32",
                                    "custom_mgmt_ip": "192.168.1.100/32",
                                },
                            }
                        ],
                    }
                ],
            }
        }

        resolver = SDWANDeviceResolver(data_model)
        device_data: dict[str, Any] = data_model["sdwan"]["sites"][0]["routers"][0]  # type: ignore[index]

        host_ip = resolver.extract_host_ip(device_data)
        # Should use custom_mgmt_ip (router-level override), not global variable
        assert host_ip == "192.168.1.100"

    def test_extract_host_ip_cidr_stripping(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Test that CIDR notation is properly stripped."""
        resolver = SDWANDeviceResolver(sample_data_model)
        device_data = sample_data_model["sdwan"]["sites"][0]["routers"][0]

        host_ip = resolver.extract_host_ip(device_data)
        # Original value is "10.1.1.1/32", should be stripped to "10.1.1.1"
        assert host_ip == "10.1.1.1"
        assert "/" not in host_ip

    def test_extract_host_ip_no_cidr(self) -> None:
        """Test IP extraction when no CIDR notation is present."""
        data_model: dict[str, Any] = {
            "sdwan": {
                "management_ip_variable": "vpn511_int1_if_ipv4_address",
                "sites": [
                    {
                        "name": "site1",
                        "routers": [
                            {
                                "chassis_id": "ABC123",
                                "device_variables": {
                                    "system_hostname": "router1",
                                    "vpn511_int1_if_ipv4_address": "10.1.1.1",  # No CIDR
                                },
                            }
                        ],
                    }
                ],
            }
        }

        resolver = SDWANDeviceResolver(data_model)
        device_data: dict[str, Any] = data_model["sdwan"]["sites"][0]["routers"][0]  # type: ignore[index]

        host_ip = resolver.extract_host_ip(device_data)
        assert host_ip == "10.1.1.1"

    def test_extract_host_ip_missing_management_ip_variable(self) -> None:
        """Test error when management_ip_variable is not configured."""
        data_model: dict[str, Any] = {
            "sdwan": {
                # No management_ip_variable at global level
                "sites": [
                    {
                        "name": "site1",
                        "routers": [
                            {
                                "chassis_id": "ABC123",
                                # No management_ip_variable at router level either
                                "device_variables": {
                                    "system_hostname": "router1",
                                    "vpn511_int1_if_ipv4_address": "10.1.1.1/32",
                                },
                            }
                        ],
                    }
                ],
            }
        }

        resolver = SDWANDeviceResolver(data_model)
        device_data: dict[str, Any] = data_model["sdwan"]["sites"][0]["routers"][0]  # type: ignore[index]

        with pytest.raises(ValueError) as exc_info:
            resolver.extract_host_ip(device_data)

        assert "management_ip_variable not configured" in str(exc_info.value)

    def test_extract_host_ip_variable_not_in_device_variables(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Test error when management_ip_variable is not found in device_variables."""
        resolver = SDWANDeviceResolver(sample_data_model)
        device_data = {
            "chassis_id": "ABC123",
            "device_variables": {
                "system_hostname": "router1",
                # Missing vpn511_int1_if_ipv4_address
            },
        }

        with pytest.raises(ValueError) as exc_info:
            resolver.extract_host_ip(device_data)

        assert "not found in device_variables" in str(exc_info.value)
        assert "vpn511_int1_if_ipv4_address" in str(exc_info.value)


class TestBuildDeviceDict:
    """Test device dictionary building."""

    def test_build_device_dict_includes_type_router(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Test that build_device_dict adds type='router' field."""
        resolver = SDWANDeviceResolver(sample_data_model)
        device_data = sample_data_model["sdwan"]["sites"][0]["routers"][0]

        device_dict = resolver.build_device_dict(device_data)

        assert device_dict["type"] == "router"

    def test_build_device_dict_includes_platform_sdwan(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Test that build_device_dict includes platform='sdwan' field."""
        resolver = SDWANDeviceResolver(sample_data_model)
        device_data = sample_data_model["sdwan"]["sites"][0]["routers"][0]

        device_dict = resolver.build_device_dict(device_data)

        assert device_dict["platform"] == "sdwan"

    def test_build_device_dict_has_all_required_fields(
        self, sample_data_model: dict[str, Any]
    ) -> None:
        """Test that device dict has all required fields."""
        resolver = SDWANDeviceResolver(sample_data_model)
        device_data = sample_data_model["sdwan"]["sites"][0]["routers"][0]

        device_dict = resolver.build_device_dict(device_data)

        required_fields = ["hostname", "host", "os", "platform", "device_id", "type"]
        for field in required_fields:
            assert field in device_dict, f"Missing required field: {field}"
            assert device_dict[field], f"Field {field} is empty"


class TestCredentialInjection:
    """Test credential injection from environment variables."""

    def test_successful_credential_injection(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test successful injection of credentials from environment variables."""
        resolver = SDWANDeviceResolver(sample_data_model)
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

        resolver = SDWANDeviceResolver(sample_data_model)

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

        resolver = SDWANDeviceResolver(sample_data_model)

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
        resolver = SDWANDeviceResolver(sample_data_model)
        devices = resolver.get_resolved_inventory()

        # Should resolve all 3 routers
        assert len(devices) == 3

        # Verify first device
        device1 = next(d for d in devices if d["device_id"] == "ABC123")
        assert device1["hostname"] == "router1"
        assert device1["host"] == "10.1.1.1"
        assert device1["os"] == "iosxe"
        assert device1["platform"] == "sdwan"
        assert device1["device_id"] == "ABC123"
        assert device1["type"] == "router"
        assert device1["username"] == "test_user"
        assert device1["password"] == "test_pass"

        # Verify device from second site
        device3 = next(d for d in devices if d["device_id"] == "GHI789")
        assert device3["hostname"] == "router3"
        assert device3["host"] == "10.2.1.1"

    def test_multiple_sites_resolution(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test that devices from multiple sites are all resolved."""
        resolver = SDWANDeviceResolver(sample_data_model)
        devices = resolver.get_resolved_inventory()

        # Should have routers from both sites
        assert len(devices) == 3

        # Check all chassis IDs are present
        chassis_ids = [d["device_id"] for d in devices]
        assert "ABC123" in chassis_ids  # Site 1
        assert "DEF456" in chassis_ids  # Site 1
        assert "GHI789" in chassis_ids  # Site 2


class TestErrorHandlingAndSkippedDevices:
    """Test error handling and skipped device tracking."""

    def test_skip_router_with_missing_chassis_id(
        self,
        mock_credentials: None,
    ) -> None:
        """Test that routers without chassis_id are skipped."""
        data_model = {
            "sdwan": {
                "management_ip_variable": "vpn511_int1_if_ipv4_address",
                "sites": [
                    {
                        "name": "site1",
                        "routers": [
                            {
                                "chassis_id": "ABC123",
                                "device_variables": {
                                    "system_hostname": "router1",
                                    "vpn511_int1_if_ipv4_address": "10.1.1.1/32",
                                },
                            },
                            {
                                # Missing chassis_id
                                "device_variables": {
                                    "system_hostname": "router2",
                                    "vpn511_int1_if_ipv4_address": "10.1.1.2/32",
                                },
                            },
                        ],
                    }
                ],
            }
        }

        resolver = SDWANDeviceResolver(data_model)
        devices = resolver.get_resolved_inventory()

        # Only 1 device should be resolved
        assert len(devices) == 1
        assert devices[0]["device_id"] == "ABC123"

        # Check skipped devices
        assert len(resolver.skipped_devices) == 1
        skipped = resolver.skipped_devices[0]
        assert "reason" in skipped
        assert "chassis_id" in skipped["reason"].lower()

    def test_skip_router_with_missing_management_ip(
        self,
        mock_credentials: None,
    ) -> None:
        """Test that routers without management IP are skipped."""
        data_model = {
            "sdwan": {
                "management_ip_variable": "vpn511_int1_if_ipv4_address",
                "sites": [
                    {
                        "name": "site1",
                        "routers": [
                            {
                                "chassis_id": "ABC123",
                                "device_variables": {
                                    "system_hostname": "router1",
                                    "vpn511_int1_if_ipv4_address": "10.1.1.1/32",
                                },
                            },
                            {
                                "chassis_id": "DEF456",
                                "device_variables": {
                                    "system_hostname": "router2",
                                    # Missing vpn511_int1_if_ipv4_address
                                },
                            },
                        ],
                    }
                ],
            }
        }

        resolver = SDWANDeviceResolver(data_model)
        devices = resolver.get_resolved_inventory()

        # Only 1 device should be resolved
        assert len(devices) == 1
        assert devices[0]["device_id"] == "ABC123"

        # Check skipped devices
        assert len(resolver.skipped_devices) == 1
        skipped = resolver.skipped_devices[0]
        assert skipped["device_id"] == "DEF456"
        assert "not found in device_variables" in skipped["reason"]

    def test_hostname_fallback_logged(
        self,
        mock_credentials: None,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test that hostname fallback to chassis_id is logged."""
        data_model = {
            "sdwan": {
                "management_ip_variable": "vpn511_int1_if_ipv4_address",
                "sites": [
                    {
                        "name": "site1",
                        "routers": [
                            {
                                "chassis_id": "ABC123",
                                "device_variables": {
                                    # No system_hostname
                                    "vpn511_int1_if_ipv4_address": "10.1.1.1/32",
                                },
                            }
                        ],
                    }
                ],
            }
        }

        with caplog.at_level("WARNING"):
            resolver = SDWANDeviceResolver(data_model)
            devices = resolver.get_resolved_inventory()

        # Device should be resolved with chassis_id as hostname
        assert len(devices) == 1
        assert devices[0]["hostname"] == "ABC123"

        # Check for warning log
        assert "No system_hostname found" in caplog.text
        assert "ABC123" in caplog.text
