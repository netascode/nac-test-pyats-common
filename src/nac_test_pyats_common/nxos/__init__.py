# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""NX-OS adapter module for NAC PyATS testing.

This module provides NX-OS-specific classes for SSH/D2D operational testing
against Nexus switches.

Classes:
    NXOSTestBase: Base class for NX-OS SSH/D2D tests.
    NXOSDeviceResolver: Resolves device inventory from the NX-OS data model.

Example:
    >>> from nac_test_pyats_common.nxos import NXOSTestBase, NXOSDeviceResolver
    >>>
    >>> class VerifyVPCStatus(NXOSTestBase):
    ...     @aetest.test
    ...     def verify_vpc(self, steps, device):
    ...         output = device.execute("show vpc")
    ...         # verify VPC state
"""

from .device_resolver import NXOSDeviceResolver
from .ssh_test_base import NXOSTestBase

__all__ = [
    "NXOSDeviceResolver",
    "NXOSTestBase",
]
