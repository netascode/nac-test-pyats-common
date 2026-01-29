# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""IOSXE device resolver placeholder for direct IOS-XE device access.

This is a placeholder for the IOSXE resolver that will be implemented
when direct IOS-XE device support is added. This resolver will handle
devices accessed directly via IOSXE_URL without a centralized controller.

Expected environment variables:
    - IOSXE_URL: URL for direct device access
    - IOSXE_USERNAME: SSH username for devices
    - IOSXE_PASSWORD: SSH password for devices
"""

from typing import Any

from nac_test_pyats_common.common import BaseDeviceResolver

from .registry import register_iosxe_resolver


@register_iosxe_resolver("IOSXE")
class IOSXEResolver(BaseDeviceResolver):
    """Placeholder resolver for direct IOS-XE device access.

    This resolver will be implemented when IOSXE_URL-based direct device
    access is supported. Currently a placeholder to reserve the IOSXE
    registry slot.
    """

    def get_architecture_name(self) -> str:
        """Return architecture name."""
        return "iosxe"

    def get_schema_root_key(self) -> str:
        """Return data model root key."""
        return "devices"

    def navigate_to_devices(self) -> list[dict[str, Any]]:
        """Navigate to devices in data model."""
        raise NotImplementedError(
            "IOSXEResolver is not yet implemented. "
            "This placeholder reserves the IOSXE registry slot for future use."
        )

    def extract_device_id(self, device_data: dict[str, Any]) -> str:
        """Extract device ID."""
        raise NotImplementedError("IOSXEResolver is not yet implemented")

    def extract_hostname(self, device_data: dict[str, Any]) -> str:
        """Extract hostname."""
        raise NotImplementedError("IOSXEResolver is not yet implemented")

    def extract_host_ip(self, device_data: dict[str, Any]) -> str:
        """Extract management IP."""
        raise NotImplementedError("IOSXEResolver is not yet implemented")

    def extract_os_platform_type(self, device_data: dict[str, Any]) -> dict[str, str]:
        """Extract OS and platform info."""
        raise NotImplementedError("IOSXEResolver is not yet implemented")

    def get_credential_env_vars(self) -> tuple[str, str]:
        """Return credential environment variable names."""
        return ("IOSXE_USERNAME", "IOSXE_PASSWORD")
