# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""NAC PyATS Common - Architecture adapters for NAC PyATS testing.

This package provides architecture-specific authentication, test base classes,
and device resolver implementations for use with the nac-test framework. It
consolidates duplicated PyATS testing infrastructure from multiple NAC
architecture repositories (ACI, SD-WAN, Catalyst Center) into a single,
centralized, and maintainable package.

Supported Architectures:
    - ACI (APIC): nac_test_pyats_common.aci
    - SD-WAN (SDWAN Manager): nac_test_pyats_common.sdwan
    - Catalyst Center: nac_test_pyats_common.catc

Example:
    >>> # For ACI/APIC testing
    >>> from nac_test_pyats_common.aci import APICTestBase
    >>>
    >>> # For SD-WAN/SDWAN Manager testing
    >>> from nac_test_pyats_common.sdwan import SDWANManagerTestBase, SDWANTestBase
    >>>
    >>> # For Catalyst Center testing
    >>> from nac_test_pyats_common.catc import CatalystCenterTestBase
"""

__version__ = "1.0.0"

# Public API - Import from subpackages
from nac_test_pyats_common.aci import APICAuth, APICTestBase
from nac_test_pyats_common.catc import (
    CatalystCenterAuth,
    CatalystCenterDeviceResolver,
    CatalystCenterSSHTestBase,
    CatalystCenterTestBase,
)
from nac_test_pyats_common.sdwan import (
    SDWANDeviceResolver,
    SDWANManagerAuth,
    SDWANManagerTestBase,
    SDWANTestBase,
)

__all__ = [
    # ACI/APIC
    "APICAuth",
    "APICTestBase",
    # SD-WAN/SDWAN Manager
    "SDWANManagerAuth",
    "SDWANManagerTestBase",
    "SDWANTestBase",
    "SDWANDeviceResolver",
    # Catalyst Center
    "CatalystCenterAuth",
    "CatalystCenterTestBase",
    "CatalystCenterSSHTestBase",
    "CatalystCenterDeviceResolver",
]
