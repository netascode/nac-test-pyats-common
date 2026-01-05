"""Catalyst Center adapter module for NAC PyATS testing.

This module provides Catalyst Center-specific authentication and test base class
implementations for use with the nac-test framework. Catalyst Center (formerly
DNA Center) is Cisco's enterprise network management platform.

Classes:
    CatalystCenterAuth: Token-based authentication with automatic endpoint detection.
    CatalystCenterTestBase: Base class for Catalyst Center API tests with tracking.

Example:
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
    ...
    ...     @aetest.test
    ...     def verify_devices(self, steps):
    ...         self.run_async_verification_test(steps)
"""

from .auth import CatalystCenterAuth
from .test_base import CatalystCenterTestBase

__all__ = [
    "CatalystCenterAuth",
    "CatalystCenterTestBase",
]
