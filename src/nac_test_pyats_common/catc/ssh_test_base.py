# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Catalyst Center specific base test class for SSH/Direct-to-Device testing.

This module provides the CatalystCenterSSHTestBase class, which extends the generic
SSHTestBase to add Catalyst Center-specific functionality for device-to-device (D2D)
testing.

The class delegates device inventory resolution to CatalystCenterDeviceResolver, which
handles all Catalyst Center schema navigation and credential injection.

Credentials:
    Catalyst Center D2D tests connect to IOS-XE devices managed by Catalyst Center,
    NOT the Catalyst Center controller. Set these environment variables:
    - IOSXE_USERNAME: SSH username for managed devices
    - IOSXE_PASSWORD: SSH password for managed devices
"""

import logging
import os
from typing import Any

from nac_test.pyats_core.common.ssh_base_test import (
    SSHTestBase,  # type: ignore[import-untyped]
)

from .device_resolver import CatalystCenterDeviceResolver

logger = logging.getLogger(__name__)


class CatalystCenterSSHTestBase(SSHTestBase):  # type: ignore[misc]
    """Catalyst Center-specific base test class for SSH/D2D testing.

    This class extends SSHTestBase and implements the contract required by
    nac-test's SSH execution engine. Device inventory resolution is fully
    delegated to CatalystCenterDeviceResolver.

    Credentials:
        Catalyst Center D2D tests require IOSXE_USERNAME and IOSXE_PASSWORD
        environment variables (NOT CC_* which are for the controller).

    Example:
        class MyCatalystCenterSSHTest(CatalystCenterSSHTestBase):
            @aetest.test
            def verify_device_connectivity(self, steps, device):
                # SSH-based verification logic here
                pass
    """

    # Class-level storage for the last resolver instance
    # This allows nac-test to access skipped_devices after calling
    # get_ssh_device_inventory()
    _last_resolver: "CatalystCenterDeviceResolver | None" = None

    @classmethod
    def get_ssh_device_inventory(
        cls, data_model: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Parse the Catalyst Center data model to retrieve the device inventory.

        This method is the entry point called by nac-test's orchestrator.
        All device inventory resolution is delegated to CatalystCenterDeviceResolver,
        which handles:
        - Schema navigation (catalyst_center.inventory.devices[])
        - Device metadata extraction (name, device_ip, etc.)
        - Credential injection (IOSXE_USERNAME, IOSXE_PASSWORD)

        After calling this method, access cls._last_resolver.skipped_devices
        to get information about devices that failed resolution.

        Args:
            data_model: The merged data model from nac-test containing all
                configuration data with resolved variables.

        Returns:
            List of device dictionaries, each containing:
            - hostname (str): Device hostname
            - host (str): Management IP address for SSH connection
            - os (str): Operating system type (e.g., "iosxe")
            - username (str): SSH username from IOSXE_USERNAME
            - password (str): SSH password from IOSXE_PASSWORD
            - device_id (str): Device identifier (name)

        Raises:
            ValueError: If IOSXE_USERNAME or IOSXE_PASSWORD env vars are not set.
        """
        logger.info(
            "CatalystCenterSSHTestBase: Resolving device inventory via "
            "CatalystCenterDeviceResolver"
        )

        cls._last_resolver = CatalystCenterDeviceResolver(data_model)
        return cls._last_resolver.get_resolved_inventory()

    def get_device_credentials(self, device: dict[str, Any]) -> dict[str, str | None]:
        """Get Catalyst Center managed device SSH credentials from env vars.

        Catalyst Center D2D tests connect to IOS-XE devices managed by
        Catalyst Center, NOT the Catalyst Center controller. Use IOSXE_*
        environment variables.

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
