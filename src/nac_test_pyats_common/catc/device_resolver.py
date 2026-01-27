# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Catalyst Center-specific device resolver for parsing the NAC data model.

This module provides the CatalystCenterDeviceResolver class, which extends
BaseDeviceResolver to implement Catalyst Center schema navigation for D2D testing.
"""

import logging
from typing import Any

from nac_test_pyats_common.common import BaseDeviceResolver
from nac_test_pyats_common.iosxe.registry import register_iosxe_resolver

logger = logging.getLogger(__name__)


@register_iosxe_resolver("CC")
class CatalystCenterDeviceResolver(BaseDeviceResolver):
    """Catalyst Center device resolver for D2D testing.

    Navigates the Catalyst Center NAC schema (catalyst_center.inventory.devices[])
    to extract device information for SSH testing.

    Schema structure:
        catalyst_center:
          inventory:
            devices:
              - name: P3-BN1
                fqdn_name: P3-BN1.cisco.eu
                device_ip: 192.168.38.1
                pid: C9300-24P
                state: PROVISION
                device_role: ACCESS
                site: Global/MAX_AREA/MAX_BUILDING

    Credentials:
        Uses IOSXE_USERNAME and IOSXE_PASSWORD environment variables
        for SSH access to managed IOS-XE devices.

    Example:
        >>> resolver = CatalystCenterDeviceResolver(data_model)
        >>> devices = resolver.get_resolved_inventory()
        >>> for device in devices:
        ...     print(f"{device['hostname']}: {device['host']}")
    """

    def get_architecture_name(self) -> str:
        """Return 'catalyst_center' as the architecture identifier.

        Returns:
            Architecture name used in logging and error messages.
        """
        return "catalyst_center"

    def get_schema_root_key(self) -> str:
        """Return 'catalyst_center' as the root key in the data model.

        Returns:
            Root key used when navigating the schema.
        """
        return "catalyst_center"

    def navigate_to_devices(self) -> list[dict[str, Any]]:
        """Navigate Catalyst Center schema: catalyst_center.inventory.devices[].

        Traverses the Catalyst Center data model structure to find all
        managed devices in the inventory.

        Returns:
            List of device dictionaries from the inventory.
        """
        devices: list[dict[str, Any]] = []
        cc_data = self.data_model.get("catalyst_center", {})
        inventory = cc_data.get("inventory", {})
        devices.extend(inventory.get("devices", []))
        return devices

    def validate_device_data(self, device_data: dict[str, Any]) -> None:
        """Validate device state before extraction.

        Skip devices with INIT or PNP states as they are not fully provisioned.

        Args:
            device_data: Device data dictionary from the data model.

        Raises:
            ValueError: If the device has an unsupported state (INIT, PNP).
        """
        state = device_data.get("state", "").upper()
        if state in ("INIT", "PNP"):
            raise ValueError(
                f"Device has unsupported state '{state}' "
                "(devices in INIT or PNP state are not fully provisioned)"
            )

    def extract_hostname(self, device_data: dict[str, Any]) -> str:
        """Extract hostname from the 'name' field.

        Uses the device name as the hostname for SSH connections.

        Args:
            device_data: Device data dictionary from the data model.

        Returns:
            Device hostname string.
        """
        name = device_data.get("name")
        if not name:
            raise ValueError("Device missing 'name' field")
        return str(name)

    def extract_host_ip(self, device_data: dict[str, Any]) -> str:
        """Extract management IP from device_ip field.

        Reads the device_ip field directly from the device data.
        Handles CIDR notation if present (e.g., "10.1.1.100/32" -> "10.1.1.100").

        Args:
            device_data: Device data dictionary from the data model.

        Returns:
            IP address string without CIDR notation (e.g., "192.168.38.1").

        Raises:
            ValueError: If device_ip field is not found.
        """
        device_ip = device_data.get("device_ip")
        if not device_ip:
            raise ValueError(
                "Device missing 'device_ip' field. "
                "Ensure device_ip is configured in the inventory."
            )

        ip_value = str(device_ip)

        # Strip CIDR notation if present
        if "/" in ip_value:
            ip_value = ip_value.split("/")[0]

        return ip_value

    def extract_os_type(self, device_data: dict[str, Any]) -> str:
        """Return 'iosxe' as all managed devices are IOS-XE based.

        Args:
            device_data: Device data dictionary (unused, OS is hardcoded).

        Returns:
            Always returns 'iosxe'.
        """
        return "iosxe"

    def get_credential_env_vars(self) -> tuple[str, str]:
        """Return IOS-XE credential env vars for managed devices.

        Catalyst Center D2D tests connect to IOS-XE devices,
        NOT the Catalyst Center controller.

        Returns:
            Tuple of (username_env_var, password_env_var).
        """
        return ("IOSXE_USERNAME", "IOSXE_PASSWORD")
