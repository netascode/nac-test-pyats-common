# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""SD-WAN-specific device resolver for parsing the NAC data model.

This module provides the SDWANDeviceResolver class, which extends
BaseDeviceResolver to implement SD-WAN schema navigation.

Device Fields Returned:
    - hostname: System hostname from device_variables.system_hostname
    - host: Management IP address (CIDR stripped)
    - os: Always 'iosxe' (SD-WAN edges are IOS-XE based)
    - platform: Always 'sdwan' (for PyATS abstraction optimization)
    - device_id: Chassis ID
    - type: Always 'router'
    - username: From IOSXE_USERNAME environment variable
    - password: From IOSXE_PASSWORD environment variable
"""

import logging
from typing import Any

from nac_test_pyats_common.common import BaseDeviceResolver
from nac_test_pyats_common.iosxe.registry import register_iosxe_resolver

logger = logging.getLogger(__name__)


@register_iosxe_resolver("SDWAN")
class SDWANDeviceResolver(BaseDeviceResolver):
    """SD-WAN device resolver for D2D testing.

    Navigates the SD-WAN NAC schema (sites[].routers[]) to extract
    device information for SSH testing.

    Schema structure:
        sdwan:
          management_ip_variable: "vpn511_int1_if_ipv4_address"  # Global default
          sites:
            - name: "site1"
              routers:
                - chassis_id: "abc123"
                  management_ip_variable: "custom_mgmt_ip"  # Router override
                  device_variables:
                    system_hostname: "router1"
                    vpn511_int1_if_ipv4_address: "10.1.1.100/32"
                    custom_mgmt_ip: "10.2.2.200/32"

    Management IP Resolution Priority:
        1. Router-level management_ip_variable (highest priority)
        2. Global sdwan-level management_ip_variable (fallback)

    Credentials:
        Uses IOSXE_USERNAME and IOSXE_PASSWORD environment variables
        because SD-WAN edge devices are IOS-XE based.

    Example:
        >>> resolver = SDWANDeviceResolver(data_model)
        >>> devices = resolver.get_resolved_inventory()
        >>> for device in devices:
        ...     print(f"{device['hostname']}: {device['host']}")
    """

    def get_architecture_name(self) -> str:
        """Return 'sdwan' as the architecture identifier.

        Returns:
            Architecture name used in logging and error messages.
        """
        return "sdwan"

    def get_schema_root_key(self) -> str:
        """Return 'sdwan' as the root key in the data model.

        Returns:
            Root key used when navigating the schema.
        """
        return "sdwan"

    def navigate_to_devices(self) -> list[dict[str, Any]]:
        """Navigate SD-WAN schema: sdwan.sites[].routers[].

        Traverses the SD-WAN data model structure to find all router
        devices across all sites.

        Returns:
            List of router dictionaries from all sites.
        """
        devices: list[dict[str, Any]] = []
        sdwan_data = self.data_model.get("sdwan", {})

        for site in sdwan_data.get("sites", []):
            routers = site.get("routers", [])
            devices.extend(routers)

        return devices

    def extract_device_id(self, device_data: dict[str, Any]) -> str:
        """Extract chassis_id as the device identifier.

        Args:
            device_data: Router data dictionary from the data model.

        Returns:
            Unique chassis_id string.

        Raises:
            ValueError: If the router is missing the chassis_id field.
        """
        chassis_id = device_data.get("chassis_id")
        if not chassis_id:
            raise ValueError("Router missing 'chassis_id' field")
        return str(chassis_id)

    def extract_hostname(self, device_data: dict[str, Any]) -> str:
        """Extract hostname from device_variables.system_hostname.

        Looks for system_hostname in the device_variables section.
        Falls back to chassis_id if system_hostname is not available.

        Args:
            device_data: Router data dictionary from the data model.

        Returns:
            Device hostname string.
        """
        device_vars = device_data.get("device_variables", {})

        if "system_hostname" in device_vars:
            return str(device_vars["system_hostname"])

        # Fallback to chassis_id
        chassis_id = device_data.get("chassis_id", "unknown")
        logger.warning(
            f"No system_hostname found for {chassis_id}, using chassis_id as hostname"
        )
        return str(chassis_id)

    def extract_host_ip(self, device_data: dict[str, Any]) -> str:
        """Extract management IP from device_variables.

        Handles CIDR notation (e.g., "10.1.1.100/32" -> "10.1.1.100").
        Uses management_ip_variable field to determine which variable
        contains the management IP.

        Resolution priority:
        1. Router-level management_ip_variable (highest priority)
        2. Global sdwan-level management_ip_variable (fallback)

        Args:
            device_data: Router data dictionary from the data model.

        Returns:
            IP address string without CIDR notation (e.g., "10.1.1.100").

        Raises:
            ValueError: If management_ip_variable is not configured or
                the referenced variable is not found in device_variables.
        """
        device_vars = device_data.get("device_variables", {})

        # Cascading lookup: router-level > global sdwan-level
        ip_var = device_data.get("management_ip_variable")
        if not ip_var:
            ip_var = self.data_model.get("sdwan", {}).get("management_ip_variable")

        if not ip_var:
            raise ValueError(
                "management_ip_variable not configured. "
                "Set it at router level or sdwan level in sites.nac.yaml."
            )

        if ip_var not in device_vars:
            raise ValueError(
                f"management_ip_variable '{ip_var}' not found in device_variables."
            )

        ip_value = str(device_vars[ip_var])

        # Strip CIDR notation if present
        if "/" in ip_value:
            ip_value = ip_value.split("/")[0]

        return ip_value

    def extract_os_platform_type(self, device_data: dict[str, Any]) -> dict[str, str]:
        """Return PyATS abstraction info for SD-WAN edge devices.

        All SD-WAN edge devices are IOS-XE based with 'sdwan' platform.

        Args:
            device_data: Router data dictionary (unused, values are hardcoded).

        Returns:
            Dictionary with 'os' and 'platform' keys.
        """
        return {
            "os": "iosxe",
            "platform": "sdwan",
        }

    def build_device_dict(self, device_data: dict[str, Any]) -> dict[str, Any]:
        """Build device dictionary with SD-WAN specific defaults.

        Extends the base implementation to add type='router'.
        Platform is set to 'sdwan' via extract_os_platform_type().

        Args:
            device_data: Router data dictionary from the data model.

        Returns:
            Device dictionary with hostname, host, os, platform, device_id, and type.
        """
        # Get base device dict from parent
        device_dict = super().build_device_dict(device_data)

        # Add type - all SD-WAN edges are routers
        device_dict["type"] = "router"

        return device_dict

    def get_credential_env_vars(self) -> tuple[str, str]:
        """Return IOS-XE credential env vars for SD-WAN edge devices.

        SD-WAN D2D tests connect to IOS-XE based edge devices,
        NOT the vManage/SDWAN Manager controller.

        Returns:
            Tuple of (username_env_var, password_env_var).
        """
        return ("IOSXE_USERNAME", "IOSXE_PASSWORD")
