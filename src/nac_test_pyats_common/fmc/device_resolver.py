# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

# SPDX-License-Identifier: MPL-2.0

"""FTD device resolver for SSH/D2D testing.

This module provides the FTDDeviceResolver class, which extends
BaseDeviceResolver to navigate the FMC data model and extract
FTD device information for SSH-based operational testing.

Device Fields Returned:
    - hostname: Device name from fmc.domains[].devices.devices[].name
    - host: Management IP from fmc.domains[].devices.devices[].host
    - os: Always 'fxos' (Firepower eXtensible OS)
    - platform: Always 'ftd' (Firepower Threat Defense)
    - username: From FTD_USERNAME environment variable
    - password: From FTD_PASSWORD environment variable

Note:
    FTD SSH credentials are SEPARATE from FMC controller credentials.
    FMC_USERNAME/FMC_PASSWORD are for the FMC REST API.
    FTD_USERNAME/FTD_PASSWORD are for SSH access to FTD devices.
"""

import logging
from typing import Any

from nac_test_pyats_common.common import BaseDeviceResolver

logger = logging.getLogger(__name__)


class FTDDeviceResolver(BaseDeviceResolver):
    """FTD device resolver for D2D testing.

    Navigates the FMC NAC data model (fmc.domains[].devices.devices[])
    to extract FTD device information for SSH testing. Devices are
    flattened across all FMC domains into a single inventory.

    Schema structure:
        fmc:
          domains:
            - name: "Global"
              devices:
                devices:
                  - name: "FTD-FW1"
                    host: "10.1.1.100"
                  - name: "FTD-FW2"
                    host: "10.1.1.101"
            - name: "Branch"
              devices:
                devices:
                  - name: "FTD-BR1"
                    host: "10.2.1.100"

    Credentials:
        Uses FTD_USERNAME and FTD_PASSWORD environment variables.
        These are for SSH access to FTD devices, NOT for the FMC controller.

    Example:
        >>> resolver = FTDDeviceResolver(data_model)
        >>> devices = resolver.get_resolved_inventory()
        >>> devices[0]["hostname"]
        'FTD-FW1'
        >>> devices[0]["os"]
        'fxos'
        >>> devices[0]["platform"]
        'ftd'
    """

    def get_architecture_name(self) -> str:
        """Return the architecture identifier."""
        return "fmc"

    def get_schema_root_key(self) -> str:
        """Return the top-level data model key."""
        return "fmc"

    def navigate_to_devices(self) -> list[dict[str, Any]]:
        """Flatten all FTD devices across FMC domains.

        Iterates fmc.domains[].devices.devices[] and collects all devices
        into a single flat list regardless of which domain they belong to.
        """
        devices: list[dict[str, Any]] = []
        fmc_data = self.data_model.get("fmc", {})
        domains = fmc_data.get("domains", [])

        for domain in domains:
            domain_devices = domain.get("devices", {})
            device_list = domain_devices.get("devices", [])
            devices.extend(device_list)

        return devices

    def extract_hostname(self, device_data: dict[str, Any]) -> str:
        """Extract device hostname from the name field."""
        return str(device_data["name"])

    def extract_host_ip(self, device_data: dict[str, Any]) -> str:
        """Extract management IP from the host field.

        The FMC data model stores the device's management IP/hostname
        directly in the 'host' field (mapped from FMC API's hostName).
        """
        host = device_data.get("host")
        if not host:
            raise ValueError("Device has no 'host' field for management IP")
        return str(host)

    def extract_os_platform_type(self, device_data: dict[str, Any]) -> dict[str, str]:
        """Return Unicon os and platform for FTD devices."""
        return {"os": "fxos", "platform": "ftd"}

    def get_credential_env_vars(self) -> tuple[str, str]:
        """Return credential environment variable names."""
        return ("FTD_USERNAME", "FTD_PASSWORD")
