# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""SD-WAN specific base test class for SSH/Direct-to-Device testing.

This module provides the SDWANTestBase class, which extends the generic SSHTestBase
to add SD-WAN-specific functionality for device-to-device (D2D) testing.

The class delegates device inventory resolution to SDWANDeviceResolver, which
handles all SD-WAN schema navigation and credential injection.

Credentials:
    SD-WAN D2D tests connect to IOS-XE based edge devices, NOT the SDWAN Manager
    controller. Set these environment variables:
    - IOSXE_USERNAME: SSH username for edge devices
    - IOSXE_PASSWORD: SSH password for edge devices
"""

import logging
import os
from typing import Any

from nac_test.pyats_core.common.ssh_base_test import SSHTestBase

from .device_resolver import SDWANDeviceResolver

logger = logging.getLogger(__name__)


class SDWANTestBase(SSHTestBase):  # type: ignore[misc]
    """SD-WAN-specific base test class for SSH/D2D testing.

    This class extends SSHTestBase and implements the contract required by
    nac-test's SSH execution engine. Device inventory resolution is fully
    delegated to SDWANDeviceResolver.

    Credentials:
        SD-WAN D2D tests require IOSXE_USERNAME and IOSXE_PASSWORD environment
        variables (NOT SDWAN_* which are for the controller).

    Example:
        class MySDWANSSHTest(SDWANTestBase):
            @aetest.test
            def verify_device_connectivity(self, steps, device):
                # SSH-based verification logic here
                pass
    """

    # Class-level storage for the last resolver instance
    # This allows nac-test to access skipped_devices after calling
    # get_ssh_device_inventory()
    _last_resolver: "SDWANDeviceResolver | None" = None

    @classmethod
    def get_ssh_device_inventory(
        cls, data_model: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Parse the SD-WAN data model to retrieve the device inventory.

        This method is the entry point called by nac-test's orchestrator.
        All device inventory resolution is delegated to SDWANDeviceResolver,
        which handles:
        - Schema navigation (sites[].routers[])
        - Management IP resolution via management_ip_variable
        - Credential injection (IOSXE_USERNAME, IOSXE_PASSWORD)

        After calling this method, access cls._last_resolver.skipped_devices
        to get information about devices that failed resolution.

        Args:
            data_model: The merged data model from nac-test containing all
                sites.nac.yaml data with resolved variables.

        Returns:
            List of device dictionaries, each containing:
            - hostname (str): Device hostname
            - host (str): Management IP address for SSH connection
            - os (str): Operating system type (e.g., "iosxe")
            - username (str): SSH username from IOSXE_USERNAME
            - password (str): SSH password from IOSXE_PASSWORD
            - device_id (str): Device identifier (chassis_id)

        Raises:
            ValueError: If IOSXE_USERNAME or IOSXE_PASSWORD env vars are not set.
        """
        logger.info("SDWANTestBase: Resolving device inventory via SDWANDeviceResolver")

        cls._last_resolver = SDWANDeviceResolver(data_model)
        return cls._last_resolver.get_resolved_inventory()

    def get_device_credentials(self, device: dict[str, Any]) -> dict[str, str | None]:
        """Get SD-WAN edge device SSH credentials from environment variables.

        SD-WAN D2D tests connect to IOS-XE edge devices (vEdge, ISR, etc.),
        NOT the SDWAN Manager controller. Use IOSXE_* environment variables.

        Args:
            device: Device dictionary (not used - all devices share credentials).

        Returns:
            Dictionary containing:
            - username (str | None): SSH username from IOSXE_USERNAME
            - password (str | None): SSH password from IOSXE_PASSWORD
        """
        return {
            "username": os.environ.get("IOSXE_USERNAME"),
            "password": os.environ.get("IOSXE_PASSWORD"),
        }
