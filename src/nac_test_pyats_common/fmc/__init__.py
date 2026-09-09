# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

# SPDX-License-Identifier: MPL-2.0

"""FMC (Firepower Management Center) adapter module for NAC PyATS testing.

This module provides FMC-specific classes for both API-based and SSH/D2D
operational testing against Cisco Firepower Management Center controllers
and the FTD devices they manage.

Classes:
    FMCAuth: Authentication handler for FMC token-based auth.
    FMCTestBase: Base class for FMC API tests.
    FTDTestBase: Base class for FTD SSH/D2D tests.
    FTDDeviceResolver: Resolves FTD device inventory from FMC data model.

Example (API test against FMC):
    >>> from nac_test_pyats_common.fmc import FMCTestBase
    >>>
    >>> class VerifyDeviceStatus(FMCTestBase):
    ...     async def get_items_to_verify(self):
    ...         return [{"device_id": "abc123"}]
    ...
    ...     async def verify_item(self, semaphore, client, context):
    ...         device_id = context['device_id']
    ...         resp = await client.get(f"/devices/devicerecords/{device_id}")
    ...         # verify device state

Example (SSH test against FTD):
    >>> from nac_test_pyats_common.fmc import FTDTestBase
    >>>
    >>> class VerifyFailoverStatus(FTDTestBase):
    ...     @aetest.test
    ...     def verify_failover(self, steps, device):
    ...         output = device.execute("show failover")
    ...         # verify failover state
"""

from .api_test_base import FMCTestBase
from .auth import FMCAuth
from .device_resolver import FTDDeviceResolver
from .ssh_test_base import FTDTestBase

__all__ = [
    "FMCAuth",
    "FMCTestBase",
    "FTDDeviceResolver",
    "FTDTestBase",
]
