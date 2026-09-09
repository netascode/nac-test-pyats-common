# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""FMC/FTD adapter module for NAC PyATS testing.

This module provides classes for SSH/D2D operational testing against
Cisco Firepower Threat Defense devices managed by FMC.

Classes:
    FTDTestBase: Base class for FTD SSH/D2D tests.
    FTDDeviceResolver: Resolves FTD device inventory from FMC data model.

Example (SSH test against FTD):
    >>> from nac_test_pyats_common.fmc import FTDTestBase
    >>>
    >>> class VerifyFailoverStatus(FTDTestBase):
    ...     @aetest.test
    ...     def verify_failover(self, steps, device):
    ...         output = device.execute("show failover")
    ...         # verify failover state
"""

from .device_resolver import FTDDeviceResolver
from .ssh_test_base import FTDTestBase

__all__ = [
    "FTDDeviceResolver",
    "FTDTestBase",
]
