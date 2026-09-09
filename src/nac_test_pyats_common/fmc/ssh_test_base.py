# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

# SPDX-License-Identifier: MPL-2.0

"""FTD-specific base test class for SSH/Direct-to-Device testing.

This module provides the FTDTestBase class, which extends the generic SSHTestBase
to add FTD-specific functionality for device-to-device (D2D) testing.

The class delegates device inventory resolution to FTDDeviceResolver, which
handles FMC data model navigation and credential injection.

Credentials:
    FTD D2D tests connect to Firepower Threat Defense devices, NOT the FMC
    controller. Set these environment variables:
    - FTD_USERNAME: SSH username for FTD devices
    - FTD_PASSWORD: SSH password for FTD devices

PyATS/Unicon Configuration:
    FTD devices use os='fxos' and platform='ftd', which activates the
    Unicon FTD plugin with its multi-state CLI (chassis, fxos, ftd_console,
    ftd_expert). The plugin handles state transitions automatically.
"""

import logging
from typing import Any

from nac_test.pyats_core.common.ssh_base_test import (
    SSHTestBase,  # type: ignore[import-untyped]
)

from .device_resolver import FTDDeviceResolver

logger = logging.getLogger(__name__)


class FTDTestBase(SSHTestBase):  # type: ignore[misc]
    """FTD-specific base test class for SSH/D2D testing.

    This class extends SSHTestBase and implements the contract required by
    nac-test's SSH execution engine. Device inventory resolution is fully
    delegated to FTDDeviceResolver.

    Credentials:
        FTD D2D tests require FTD_USERNAME and FTD_PASSWORD environment
        variables (NOT FMC_* which are for the controller API).

    Example:
        class MyFTDTest(FTDTestBase):
            @aetest.test
            def verify_failover_status(self, steps, device):
                # SSH-based verification on FTD device
                output = device.execute("show failover")
                # process output...
    """

    _last_resolver: "FTDDeviceResolver | None" = None

    @classmethod
    def get_ssh_device_inventory(
        cls, data_model: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Parse the FMC data model to retrieve FTD device inventory.

        This method is the entry point called by nac-test's orchestrator.
        All device inventory resolution is delegated to FTDDeviceResolver,
        which handles:
        - Schema navigation (fmc.domains[].devices.devices[])
        - Flattening devices across all FMC domains
        - Credential injection (FTD_USERNAME, FTD_PASSWORD)

        After calling this method, access cls._last_resolver.skipped_devices
        to get information about devices that failed resolution.

        Args:
            data_model: The merged data model from nac-test containing all
                FMC configuration data with resolved variables.

        Returns:
            List of device dictionaries, each containing:
            - hostname (str): FTD device name
            - host (str): Management IP address for SSH connection
            - os (str): Always "fxos"
            - platform (str): Always "ftd"
            - username (str): Environment variable reference
            - password (str): Environment variable reference
        """
        resolver = FTDDeviceResolver(data_model)
        cls._last_resolver = resolver
        return resolver.get_resolved_inventory()
