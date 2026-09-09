# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""NX-OS device resolver for SSH/D2D testing.

This module provides the NXOSDeviceResolver class, which extends
BaseDeviceResolver to implement NX-OS data model navigation.

Device Fields Returned:
    - hostname: Device name from nxos.devices[].name
    - host: Management IP extracted from nxos.devices[].url
    - os: Always 'nxos'
    - platform: Always 'nexus'
    - username: From NXOS_USERNAME environment variable
    - password: From NXOS_PASSWORD environment variable
"""

import logging
from typing import Any
from urllib.parse import urlparse

from nac_test_pyats_common.common import BaseDeviceResolver

logger = logging.getLogger(__name__)


class NXOSDeviceResolver(BaseDeviceResolver):
    """NX-OS device resolver for D2D testing.

    Navigates the NX-OS NAC schema (nxos.devices[]) to extract
    device information for SSH testing.

    Schema structure:
        nxos:
          devices:
            - name: "N9K-1"
              url: "https://10.48.161.104"
              managed: true  # optional

    Credentials:
        Uses NXOS_USERNAME and NXOS_PASSWORD environment variables.

    Example:
        >>> resolver = NXOSDeviceResolver(data_model)
        >>> devices = resolver.get_resolved_inventory()
        >>> devices[0]["hostname"]
        'N9K-1'
        >>> devices[0]["host"]
        '10.48.161.104'
        >>> devices[0]["os"]
        'nxos'
    """

    def get_architecture_name(self) -> str:
        """Return the architecture identifier."""
        return "nxos"

    def get_schema_root_key(self) -> str:
        """Return the top-level data model key."""
        return "nxos"

    def navigate_to_devices(self) -> list[dict[str, Any]]:
        """Navigate nxos.devices[] in the data model."""
        devices: list[dict[str, Any]] = self.data_model.get("nxos", {}).get(
            "devices", []
        )
        return devices

    def validate_device_data(self, device_data: dict[str, Any]) -> None:
        """Skip devices where managed is explicitly False."""
        if device_data.get("managed") is False:
            raise ValueError("Device has managed=false, skipping")

    def extract_hostname(self, device_data: dict[str, Any]) -> str:
        """Extract device hostname from the name field."""
        return str(device_data["name"])

    def extract_host_ip(self, device_data: dict[str, Any]) -> str:
        """Extract management IP from the device URL field.

        The NX-OS data model stores the RESTCONF URL (e.g., "https://10.48.161.104").
        We parse the hostname/IP from this URL.
        """
        url = device_data["url"]
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            raise ValueError(f"Cannot extract host from URL: {url!r}")
        return str(host)

    def extract_os_platform_type(self, device_data: dict[str, Any]) -> dict[str, str]:
        """Return Unicon os and platform for NX-OS devices."""
        return {"os": "nxos", "platform": "nexus"}

    def get_credential_env_vars(self) -> tuple[str, str]:
        """Return credential environment variable names."""
        return ("NXOS_USERNAME", "NXOS_PASSWORD")
