# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Catalyst Center adapter module for NAC PyATS testing.

This module provides Catalyst Center-specific authentication, test base classes, and
device resolver implementations for use with the nac-test framework. It includes support
for both Catalyst Center API testing and SSH-based device-to-device (D2D) testing.

Classes:
    CatalystCenterAuth: Token-based authentication with automatic endpoint
        detection.
    CatalystCenterTestBase: Base class for Catalyst Center API tests with
        tracking.
    CatalystCenterSSHTestBase: Base class for Catalyst Center SSH/D2D tests
        with device inventory.
    CatalystCenterDeviceResolver: Resolves device information from the
        Catalyst Center data model.

Example:
    For Catalyst Center API testing:

    >>> from nac_test_pyats_common.catc import CatalystCenterTestBase
    >>>
    >>> class VerifyNetworkDevices(CatalystCenterTestBase):
    ...     async def get_items_to_verify(self):
    ...         return ['device-uuid-1', 'device-uuid-2']
    ...
    ...     async def verify_item(self, item):
    ...         response = await self.client.get(
    ...             f"/dna/intent/api/v1/network-device/{item}"
    ...         )
    ...         return response.status_code == 200

    For SSH/D2D testing:

    >>> from nac_test_pyats_common.catc import CatalystCenterSSHTestBase
    >>>
    >>> class VerifyInterfaceStatus(CatalystCenterSSHTestBase):
    ...     @aetest.test
    ...     def verify_interfaces(self, steps, device):
    ...         # SSH-based verification
    ...         pass
"""

from .api_test_base import CatalystCenterTestBase
from .auth import CatalystCenterAuth
from .device_resolver import CatalystCenterDeviceResolver
from .ssh_test_base import CatalystCenterSSHTestBase

__all__ = [
    "CatalystCenterAuth",
    "CatalystCenterTestBase",
    "CatalystCenterSSHTestBase",
    "CatalystCenterDeviceResolver",
]
