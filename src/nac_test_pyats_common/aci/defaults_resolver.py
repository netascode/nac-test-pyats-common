# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Standalone defaults resolution utilities for ACI data models.

This module provides pure utility functions for reading default values from
ACI as Code data models. These functions have NO PyATS dependencies and can
be used in any context where defaults need to be read from the merged data model.

The ACI as Code framework provides a defaults file (defaults.nac.yaml) that gets
merged into the data model as a separate 'defaults' block at the root level.
These functions provide consistent access to that defaults block.

Example:
    from nac_test_pyats_common.aci.defaults_resolver import get_default_value

    # Read a single default value
    default_pod = get_default_value(data_model, "tenants.l3outs.nodes.pod")

    # Cascade lookup - returns first non-None value found
    default_pod = get_default_value(
        data_model,
        "tenants.l3outs.nodes.pod",
        "tenants.l3outs.node_profiles.nodes.pod",
    )
"""

from typing import Any

import jmespath

# Module-level constants for defaults handling
DEFAULT_APIC_PREFIX: str = "defaults.apic"
"""Default JMESPath prefix for APIC defaults in the data model.

The ACI as Code defaults file places all default values under `defaults.apic`
in the merged data model. This constant provides the standard prefix used
when constructing full JMESPath queries.
"""

DEFAULT_MISSING_ERROR: str = (
    "Defaults block not found in data model. "
    "The ACI defaults file (defaults.nac.yaml) must be passed to nac-test. "
    "Example: nac-test -d ./data -d ./defaults/defaults.nac.yaml -t ./tests/"
)
"""Default error message when the defaults block is missing from the data model.

This message is raised when the defaults file was not passed to nac-test,
resulting in a missing `defaults.apic` block in the merged data model.
"""


def ensure_defaults_block_exists(
    data_model: dict[str, Any],
    defaults_prefix: str = DEFAULT_APIC_PREFIX,
    missing_error: str = DEFAULT_MISSING_ERROR,
) -> None:
    """Validate that the defaults block exists in the data model.

    This function performs a simple existence check for the defaults block
    in the merged data model. It should be called before attempting to read
    any default values to provide a clear error message when the defaults
    file was not passed to nac-test.

    Args:
        data_model: The merged NAC data model containing configuration data
            and defaults. This is typically the result of nac-test merging
            all data files (-d arguments) together.
        defaults_prefix: JMESPath prefix for the defaults block.
            Defaults to "defaults.apic" for standard ACI configurations.
        missing_error: Error message to raise if defaults block is missing.
            Defaults to a user-friendly message explaining how to fix the issue.

    Raises:
        ValueError: If the defaults block specified by `defaults_prefix` is
            missing from the data model, indicating the defaults file was not
            passed to nac-test.

    Example:
        # Validate defaults exist before accessing them
        ensure_defaults_block_exists(data_model)

        # With custom prefix for different controller types
        ensure_defaults_block_exists(
            data_model,
            defaults_prefix="defaults.sdwan",
            missing_error="SD-WAN defaults file required",
        )
    """
    if jmespath.search(defaults_prefix, data_model) is None:
        raise ValueError(missing_error)


def get_default_value(
    data_model: dict[str, Any],
    *default_paths: str,
    required: bool = True,
    defaults_prefix: str = DEFAULT_APIC_PREFIX,
    missing_error: str = DEFAULT_MISSING_ERROR,
) -> Any:
    """Read default value(s) from the defaults block in the merged data model.

    ACI as Code provides a defaults file (defaults.nac.yaml) that gets merged
    into the data model as a separate 'defaults' block at the root level.

    This function supports both single-path lookups and cascade/fallback behavior
    across multiple paths. When multiple paths are provided, the first non-None
    value found is returned (cascade behavior).

    Note on Return Type:
        The return type is intentionally `Any` because JMESPath queries can return
        any type (str, int, float, bool, dict, list, None) depending on the data
        model structure. This is not a type safety failure - the return type is
        genuinely dynamic and depends on what's stored at the queried path.

        Callers typically know the expected type from context:
            default_pod: int = get_default_value(data, "tenants.l3outs.nodes.pod")
            default_name: str = get_default_value(data, "tenants.vrf.name")
            default_settings: dict = get_default_value(data, "tenants.settings")

        The `Any` return type accurately reflects JMESPath's runtime behavior where
        the same function can return different types based on the query path and
        data model contents. Type narrowing should be done by the caller based on
        their knowledge of the data model schema.

    Args:
        data_model: The merged NAC data model containing configuration data
            and defaults. This is typically the result of nac-test merging
            all data files (-d arguments) together.
        *default_paths: One or more JMESPaths relative to the defaults prefix.
            Single path: get_default_value(data, "tenants.l3outs.nodes.pod")
            Cascade: get_default_value(data, "path1", "path2", "path3")
        required: If True (default), raises ValueError when no default is found.
            Set to False only for truly optional defaults.
        defaults_prefix: JMESPath prefix for the defaults block.
            Defaults to "defaults.apic" for standard ACI configurations.
        missing_error: Error message to raise if defaults block is missing.
            Defaults to a user-friendly message explaining how to fix the issue.

    Returns:
        The first non-None default value found from the provided paths.
        Returns None only if required=False and no defaults exist.
        Note: When required=True (default), this function never returns None -
        it either returns a value or raises ValueError.

    Raises:
        TypeError: If no paths are provided.
        ValueError: If the defaults block is missing (defaults file not
            passed) or if none of the paths contain values (when required=True).

    Examples:
        # Single path (most common):
        default_pod = get_default_value(data_model, "tenants.l3outs.nodes.pod")

        # Cascade - try multiple paths, return first found:
        default_pod = get_default_value(
            data_model,
            "tenants.l3outs.nodes.pod",
            "tenants.l3outs.node_profiles.nodes.pod",
        )

        # Optional - returns None instead of raising if not found:
        value = get_default_value(
            data_model, "tenants.l3outs.nodes.pod", required=False
        )

        # With custom prefix for different controller types:
        value = get_default_value(
            data_model,
            "feature_templates.name",
            defaults_prefix="defaults.sdwan",
        )
    """
    if not default_paths:
        raise TypeError(
            "get_default_value() requires at least one path argument. "
            "Example: get_default_value(data_model, 'tenants.l3outs.nodes.pod')"
        )

    ensure_defaults_block_exists(data_model, defaults_prefix, missing_error)

    for path in default_paths:
        full_path = f"{defaults_prefix}.{path}"
        value = jmespath.search(full_path, data_model)
        if value is not None:
            return value

    if required:
        if len(default_paths) == 1:
            raise ValueError(
                f"Required default not found at path: "
                f"{defaults_prefix}.{default_paths[0]}. "
                f"Please verify the defaults file contains this configuration."
            )
        else:
            paths_tried = ", ".join(f"{defaults_prefix}.{p}" for p in default_paths)
            raise ValueError(
                f"Required default not found in any of {len(default_paths)} paths: "
                f"{paths_tried}. "
                f"Please verify the defaults file contains at least one of these "
                f"configurations."
            )

    return None
