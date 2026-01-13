# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Base device resolver for SSH/D2D testing.

Provides the Template Method pattern for device inventory resolution.
Architecture-specific resolvers extend this class and implement the
abstract methods for schema navigation and credential retrieval.
"""

import logging
import os
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class BaseDeviceResolver(ABC):
    """Abstract base class for architecture-specific device resolvers.

    This class implements the Template Method pattern for device inventory
    resolution. It handles common logic (credential injection, device dict
    construction) while delegating schema-specific work to abstract methods.

    Subclasses MUST implement:
        - get_architecture_name(): Return architecture identifier (e.g., "sdwan")
        - get_schema_root_key(): Return the root key in data model (e.g., "sdwan")
        - navigate_to_devices(): Navigate schema to get iterable of device data
        - extract_device_id(): Extract unique device identifier from device data
        - extract_hostname(): Extract hostname from device data
        - extract_host_ip(): Extract management IP from device data
        - extract_os_type(): Extract OS type from device data
        - get_credential_env_vars(): Return (username_env_var, password_env_var)

    Subclasses MAY override:
        - build_device_dict(): Customize device dict construction

    Attributes:
        data_model: The merged NAC data model dictionary.
        skipped_devices: List of dicts with device_id and reason for devices
            that failed resolution. Populated after get_resolved_inventory().

    Example:
        >>> class SDWANDeviceResolver(BaseDeviceResolver):
        ...     def get_architecture_name(self) -> str:
        ...         return "sdwan"
        ...
        ...     def get_schema_root_key(self) -> str:
        ...         return "sdwan"
        ...
        ...     # ... implement other abstract methods ...
        >>>
        >>> resolver = SDWANDeviceResolver(data_model)
        >>> devices = resolver.get_resolved_inventory()
    """

    def __init__(self, data_model: dict[str, Any]) -> None:
        """Initialize the device resolver.

        Args:
            data_model: The merged NAC data model containing all architecture
                data with resolved variables.
        """
        self.data_model = data_model
        self.skipped_devices: list[dict[str, str]] = []
        logger.debug(f"Initialized {self.get_architecture_name()} resolver")

    def get_resolved_inventory(self) -> list[dict[str, Any]]:
        """Get resolved device inventory ready for SSH connection.

        This is the main entry point. It:
        1. Navigates the data model to find device data
        2. Extracts hostname and management IP from each device
        3. Sets OS type (architecture-specific, e.g., hardcoded to 'iosxe' for SD-WAN)
        4. Injects SSH credentials from environment variables
        5. Returns list of device dicts ready for nac-test

        Returns:
            List of device dictionaries with all required fields:
            - hostname (str)
            - host (str)
            - os (str)
            - username (str)
            - password (str)
            - Plus any architecture-specific fields

        Raises:
            ValueError: If credential environment variables are not set.
        """
        logger.info(f"Resolving device inventory for {self.get_architecture_name()}")

        resolved_devices: list[dict[str, Any]] = []
        self.skipped_devices = []  # Reset for each resolution
        all_devices = list(self.navigate_to_devices())
        logger.debug(f"Found {len(all_devices)} devices in data model")

        for device_data in all_devices:
            try:
                device_dict = self.build_device_dict(device_data)

                # Validate extracted fields
                if not device_dict.get("hostname"):
                    raise ValueError("hostname is empty or missing")
                if not device_dict.get("host"):
                    raise ValueError("host (IP address) is empty or missing")
                if not device_dict.get("os"):
                    raise ValueError("os type is empty or missing")
                if not device_dict.get("device_id"):
                    raise ValueError("device_id is empty or missing")

                resolved_devices.append(device_dict)
                logger.debug(
                    f"Resolved device: {device_dict['hostname']} "
                    f"({device_dict['host']}, {device_dict['os']})"
                )
            except (KeyError, ValueError) as e:
                device_id = self._safe_extract_device_id(device_data)
                logger.debug(f"Skipping device {device_id}: {e}")
                self.skipped_devices.append({
                    "device_id": device_id,
                    "reason": str(e),
                })
                continue

        # Inject credentials (fail fast if missing)
        self._inject_credentials(resolved_devices)

        logger.info(
            f"Resolved {len(resolved_devices)} devices for "
            f"{self.get_architecture_name()} D2D testing"
            f"{f', skipped {len(self.skipped_devices)}' if self.skipped_devices else ''}"
        )
        return resolved_devices

    def build_device_dict(self, device_data: dict[str, Any]) -> dict[str, Any]:
        """Build a device dictionary from raw device data.

        Override this method to customize device dict construction
        for your architecture.

        Args:
            device_data: Raw device data from the data model.

        Returns:
            Device dictionary with hostname, host, os, device_id fields.
            Credentials are injected separately.

        Raises:
            ValueError: If any required field extraction fails.
        """
        hostname = self.extract_hostname(device_data)
        host = self.extract_host_ip(device_data)
        os_type = self.extract_os_type(device_data)
        device_id = self.extract_device_id(device_data)

        # Validate all extracted values are non-empty strings
        if not isinstance(hostname, str) or not hostname:
            raise ValueError(f"Invalid hostname: {hostname!r}")
        if not isinstance(host, str) or not host:
            raise ValueError(f"Invalid host IP: {host!r}")
        if not isinstance(os_type, str) or not os_type:
            raise ValueError(f"Invalid OS type: {os_type!r}")
        if not isinstance(device_id, str) or not device_id:
            raise ValueError(f"Invalid device ID: {device_id!r}")

        return {
            "hostname": hostname,
            "host": host,
            "os": os_type,
            "device_id": device_id,
        }

    # -------------------------------------------------------------------------
    # Private helper methods
    # -------------------------------------------------------------------------

    def _safe_extract_device_id(self, device_data: dict[str, Any]) -> str:
        """Safely extract device ID, returning empty string on failure."""
        try:
            return self.extract_device_id(device_data)
        except (KeyError, ValueError):
            return "<unknown>"

    def _inject_credentials(self, devices: list[dict[str, Any]]) -> None:
        """Inject SSH credentials from environment variables.

        Args:
            devices: List of device dicts to update in place.

        Raises:
            ValueError: If required credential environment variables are not set.
        """
        username_var, password_var = self.get_credential_env_vars()
        username = os.environ.get(username_var)
        password = os.environ.get(password_var)

        # FAIL FAST - raise error if credentials missing
        missing_vars: list[str] = []
        if not username:
            missing_vars.append(username_var)
        if not password:
            missing_vars.append(password_var)

        if missing_vars:
            raise ValueError(
                f"Missing required credential environment variables: "
                f"{', '.join(missing_vars)}. "
                f"These are required for {self.get_architecture_name()} D2D testing."
            )

        logger.debug(f"Injecting credentials from {username_var} and {password_var}")
        for device in devices:
            device["username"] = username
            device["password"] = password

    # -------------------------------------------------------------------------
    # Abstract methods - MUST be implemented by subclasses
    # -------------------------------------------------------------------------

    @abstractmethod
    def get_architecture_name(self) -> str:
        """Return the architecture identifier.

        Used for logging and error messages.

        Returns:
            Architecture name (e.g., "sdwan", "aci", "catc").
        """
        ...

    @abstractmethod
    def get_schema_root_key(self) -> str:
        """Return the root key in the data model for this architecture.

        Used when navigating the schema.

        Returns:
            Root key (e.g., "sdwan", "apic", "cc").
        """
        ...

    @abstractmethod
    def navigate_to_devices(self) -> list[dict[str, Any]]:
        """Navigate the data model to find all devices.

        This is where architecture-specific schema navigation happens.
        Implement this to traverse your NAC schema structure.

        Returns:
            Iterable of device data dictionaries from the data model.

        Example (SD-WAN):
            >>> def navigate_to_devices(self):
            ...     devices = []
            ...     for site in self.data_model.get("sdwan", {}).get("sites", []):
            ...         devices.extend(site.get("routers", []))
            ...     return devices
        """
        ...

    @abstractmethod
    def extract_device_id(self, device_data: dict[str, Any]) -> str:
        """Extract unique device identifier from device data.

        Args:
            device_data: Device data dict from navigate_to_devices().

        Returns:
            Unique device identifier string.

        Example (SD-WAN):
            >>> def extract_device_id(self, device_data):
            ...     return device_data["chassis_id"]
        """
        ...

    @abstractmethod
    def extract_hostname(self, device_data: dict[str, Any]) -> str:
        """Extract device hostname from device data.

        Args:
            device_data: Device data dict from navigate_to_devices().

        Returns:
            Device hostname string.

        Example (SD-WAN):
            >>> def extract_hostname(self, device_data):
            ...     return device_data["device_variables"]["system_hostname"]
        """
        ...

    @abstractmethod
    def extract_host_ip(self, device_data: dict[str, Any]) -> str:
        """Extract management IP address from device data.

        Should handle any IP formatting (e.g., strip CIDR notation).

        Args:
            device_data: Device data dict from navigate_to_devices().

        Returns:
            IP address string (e.g., "10.1.1.100").

        Example (SD-WAN):
            >>> def extract_host_ip(self, device_data):
            ...     ip_var = device_data.get("management_ip_variable")
            ...     ip = device_data["device_variables"].get(ip_var, "")
            ...     return ip.split("/")[0] if "/" in ip else ip
        """
        ...

    @abstractmethod
    def extract_os_type(self, device_data: dict[str, Any]) -> str:
        """Extract operating system type from device data.

        Args:
            device_data: Device data dict from navigate_to_devices().

        Returns:
            OS type string (e.g., "iosxe", "nxos", "iosxr").

        Example (SD-WAN):
            >>> def extract_os_type(self, device_data):
            ...     return device_data.get("os", "iosxe")
        """
        ...

    @abstractmethod
    def get_credential_env_vars(self) -> tuple[str, str]:
        """Return environment variable names for SSH credentials.

        Each architecture uses different env vars for device credentials.
        These are separate from controller credentials.

        Returns:
            Tuple of (username_env_var, password_env_var).

        Example (SD-WAN D2D uses IOS-XE devices):
            >>> def get_credential_env_vars(self):
            ...     return ("IOSXE_USERNAME", "IOSXE_PASSWORD")

        Example (ACI D2D uses NX-OS switches):
            >>> def get_credential_env_vars(self):
            ...     return ("NXOS_SSH_USERNAME", "NXOS_SSH_PASSWORD")
        """
        ...
