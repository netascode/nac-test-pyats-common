# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""IOS-XE test base class for SSH/D2D testing."""

import logging
import os
from typing import Any

from nac_test.pyats_core.common.ssh_base_test import SSHTestBase
from nac_test.utils.controller import detect_controller_type

from .registry import get_resolver_for_controller

logger = logging.getLogger(__name__)


class IOSXETestBase(SSHTestBase):  # type: ignore[misc]
    """Base class for IOS-XE device testing via SSH.

    Provides device inventory resolution for multiple architectures:
    - SD-WAN (via vManage)
    - Catalyst Center
    - IOS-XE (direct device access via IOSXE_URL)
    """

    # Class-level storage for the last resolver instance
    # This allows nac-test to access skipped_devices after calling
    # get_ssh_device_inventory()
    _last_resolver: Any = None

    @classmethod
    def get_ssh_device_inventory(
        cls, data_model: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Get the SSH device inventory for IOS-XE devices.

        Main entry point that detects the architecture and returns
        the resolved device inventory. Performs inline validation
        of controller type and data model structure.

        Args:
            data_model: The merged data model from nac-test containing all
                configuration data with resolved variables.

        Returns:
            List of device dictionaries with connection details.

        Raises:
            ValueError: If controller type is unsupported or data validation fails.
        """
        # Try to detect controller type from environment
        controller_type = detect_controller_type()

        # If no controller detected, infer from data model
        if controller_type == "UNKNOWN":
            controller_type = cls._infer_architecture_from_data_model(data_model)

        # Inline validation: Check if controller supports IOS-XE
        supported_controllers = {"SDWAN", "CC", "IOSXE"}
        if controller_type not in supported_controllers:
            raise ValueError(
                f"Controller type '{controller_type}' does not support IOS-XE devices. "
                f"Supported types: {', '.join(sorted(supported_controllers))}"
            )

        # Get resolver from registry
        resolver_class = get_resolver_for_controller(controller_type)
        if resolver_class is None:
            raise ValueError(
                f"No device resolver registered for controller type '{controller_type}'"
            )
        resolver = resolver_class(data_model)
        cls._last_resolver = resolver  # Store for skipped_devices access

        # Inline validation: Check data model has expected root key
        expected_keys = {
            "SDWAN": "sdwan",
            "CC": "catalyst_center",
            "IOSXE": "devices",
        }
        expected_key = expected_keys.get(controller_type)
        if expected_key and expected_key not in data_model:
            raise ValueError(
                f"Data model missing expected root key '{expected_key}' "
                f"for {controller_type} architecture"
            )

        # Return resolved inventory
        return resolver.get_resolved_inventory()

    @classmethod
    def _infer_architecture_from_data_model(cls, data_model: dict[str, Any]) -> str:
        """Infer architecture from data model structure when no controller is present.

        Examines the root keys in the data model to determine which
        architecture is being used.

        Args:
            data_model: The merged data model to examine.

        Returns:
            Inferred controller type string.
        """
        # Check for architecture-specific root keys
        if "sdwan" in data_model:
            return "SDWAN"
        elif "catalyst_center" in data_model:
            return "CC"
        elif "devices" in data_model:
            return "IOSXE"
        else:
            # Default to IOS-XE if no recognized structure
            return "IOSXE"

    @staticmethod
    def get_excluded_features(
        router: dict[str, Any], config_group: dict[str, Any]
    ) -> set[str]:
        """Return SD-WAN feature names that should be skipped for this router.

        Dual-device configuration groups assign features to specific devices via
        ``device_tags``. Features tagged for the OTHER device in the pair are
        excluded for this router.

        Detection order:
            1. SD-WAN 20.18+ — match by ``router.topology_label``.
            2. SD-WAN 20.15 and earlier — match by ``router.tags``.
            3. No ``device_tags`` on the config group, or no router metadata —
               returns an empty set (no exclusion).

        Args:
            router: Router dictionary from ``sdwan.sites[].routers[]``.
            config_group: Configuration group dictionary from
                ``sdwan.configuration_groups[]``.

        Returns:
            Set of feature names assigned to the OTHER device in a dual-device
            pair, which the caller should skip when iterating BGP, OSPF, OMP, or
            other UX 2.0 feature definitions.
        """
        device_tags = config_group.get("device_tags") or []
        if not device_tags:
            return set()

        topology_label = router.get("topology_label")
        if topology_label:
            return {
                feature
                for tag in device_tags
                if tag.get("name") != topology_label
                for feature in (tag.get("features") or [])
            }

        tags = router.get("tags") or []
        if tags:
            return {
                feature
                for tag in device_tags
                if tag.get("name") not in tags
                for feature in (tag.get("features") or [])
            }

        logger.warning(
            "Configuration group %r has device_tags but router %r has neither "
            "topology_label nor tags; no features will be excluded.",
            config_group.get("name"),
            router.get("hostname") or router.get("chassis_id"),
        )
        return set()

    def get_device_credentials(self, device: dict[str, Any]) -> dict[str, str | None]:
        """Get IOS-XE device credentials from environment.

        Args:
            device: Device dictionary (not used - all devices share credentials).

        Returns:
            Dictionary containing:
            - username (str | None): SSH username from IOSXE_USERNAME
            - password (str | None): SSH password from IOSXE_PASSWORD
        """
        return {
            "username": os.environ.get("IOSXE_USERNAME"),
            "password": os.environ.get("IOSXE_PASSWORD"),
        }
