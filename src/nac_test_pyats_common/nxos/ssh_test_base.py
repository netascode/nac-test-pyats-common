# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""NX-OS specific base test class for SSH/Direct-to-Device testing.

This module provides the NXOSTestBase class, which extends the generic SSHTestBase
to add NX-OS-specific functionality for device-to-device (D2D) testing.

The class delegates device inventory resolution to NXOSDeviceResolver, which
handles all NX-OS schema navigation and credential injection.

Credentials:
    NX-OS D2D tests connect directly to Nexus switches. Set these environment
    variables:
    - NXOS_USERNAME: SSH username for NX-OS devices
    - NXOS_PASSWORD: SSH password for NX-OS devices
"""

import logging
from typing import Any

from nac_test.pyats_core.common.ssh_base_test import (
    SSHTestBase,  # type: ignore[import-untyped]
)

from .device_resolver import NXOSDeviceResolver

logger = logging.getLogger(__name__)


class NXOSTestBase(SSHTestBase):  # type: ignore[misc]
    """NX-OS-specific base test class for SSH/D2D testing.

    This class extends SSHTestBase and implements the contract required by
    nac-test's SSH execution engine. Device inventory resolution is fully
    delegated to NXOSDeviceResolver.

    Credentials:
        NX-OS D2D tests require NXOS_USERNAME and NXOS_PASSWORD environment
        variables.

    Example:
        class MyNXOSTest(NXOSTestBase):
            @aetest.test
            def verify_bgp_neighbors(self, steps, device):
                # SSH-based verification logic here
                pass
    """

    _last_resolver: "NXOSDeviceResolver | None" = None

    @classmethod
    def get_ssh_device_inventory(
        cls, data_model: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Parse the NX-OS data model to retrieve the device inventory.

        This method is the entry point called by nac-test's orchestrator.
        All device inventory resolution is delegated to NXOSDeviceResolver,
        which handles:
        - Schema navigation (nxos.devices[])
        - URL-to-IP extraction
        - Credential injection (NXOS_USERNAME, NXOS_PASSWORD)

        After calling this method, access cls._last_resolver.skipped_devices
        to get information about devices that failed resolution.

        Args:
            data_model: The merged data model from nac-test containing all
                configuration data with resolved variables.

        Returns:
            List of device dictionaries, each containing:
            - hostname (str): Device name
            - host (str): Management IP address for SSH connection
            - os (str): Always "nxos"
            - platform (str): Always "nexus"
            - username (str): Environment variable reference
            - password (str): Environment variable reference
        """
        resolver = NXOSDeviceResolver(data_model)
        cls._last_resolver = resolver
        return resolver.get_resolved_inventory()
