# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""IOS-XE test base class for SSH/D2D testing."""

import logging
import os
from typing import Any

from nac_test.core.controller import get_controller_context
from nac_test.pyats_core.common.ssh_base_test import SSHTestBase

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
        # Try to get controller type from resolved context
        try:
            ctx = get_controller_context()
            controller_type = ctx.controller_type
        except (ValueError, KeyError):
            controller_type = "UNKNOWN"

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
            1. SD-WAN 20.18+ — match by ``router.topology_label`` when it is a
               non-empty string.
            2. SD-WAN 20.15 and earlier — match by any non-empty string in
               ``router.tags``.

        The result is always an empty set on any detection failure (fail-safe:
        over-test rather than silently skip). The following branches return an
        empty set:

            * No ``device_tags`` on the config group — silent, nothing to
              exclude.
            * Router has neither a usable ``topology_label`` nor any usable
              ``tags`` — logs a WARNING and returns an empty set.
            * Router identifier matches no ``device_tags[].name`` (typo,
              rename, or migration bug) — logs a WARNING and returns an empty
              set.
            * A ``device_tags`` entry has ``features`` that is neither ``None``
              nor a list — logs a WARNING and skips that entry.

        Args:
            router: Router dictionary from ``sdwan.sites[].routers[]``.
            config_group: Configuration group dictionary from
                ``sdwan.configuration_groups[]``.

        Returns:
            Set of feature names assigned to the OTHER device in a dual-device
            pair, which the caller should skip when iterating BGP, OSPF, OMP,
            or other UX 2.0 feature definitions.
        """
        device_tags = config_group.get("device_tags") or []
        if not device_tags:
            return set()

        group_name = config_group.get("name")
        router_identity = router.get("hostname") or router.get("chassis_id")

        topology_label = router.get("topology_label")
        if isinstance(topology_label, str) and topology_label:
            router_tag_names: list[str] = [topology_label]
        else:
            raw_tags = router.get("tags") or []
            router_tag_names = (
                [t for t in raw_tags if isinstance(t, str) and t]
                if isinstance(raw_tags, list)
                else []
            )

        if not router_tag_names:
            logger.warning(
                "Configuration group %r has device_tags but router %r has "
                "neither topology_label nor tags; no features will be excluded.",
                group_name,
                router_identity,
            )
            return set()

        device_tag_names = {
            tag.get("name") for tag in device_tags if isinstance(tag.get("name"), str)
        }
        if device_tag_names.isdisjoint(router_tag_names):
            logger.warning(
                "Router %r identifier(s) %r match no device_tags in "
                "configuration group %r; no features will be excluded.",
                router_identity,
                router_tag_names,
                group_name,
            )
            return set()

        excluded: set[str] = set()
        for tag in device_tags:
            name = tag.get("name")
            if not isinstance(name, str) or name in router_tag_names:
                continue
            features = tag.get("features")
            if features is None:
                continue
            if not isinstance(features, list):
                logger.warning(
                    "Configuration group %r device_tag %r has features of type "
                    "%s (expected list); ignoring.",
                    group_name,
                    name,
                    type(features).__name__,
                )
                continue
            excluded.update(f for f in features if isinstance(f, str))
        return excluded

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
