# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Environment variable helpers shared across auth modules."""

import os


def require_env_vars(*var_names: str) -> dict[str, str]:
    """Read environment variables and raise if any are missing or empty.

    Args:
        *var_names: Names of the required environment variables.

    Returns:
        A dictionary mapping each variable name to its non-empty string value.

    Raises:
        ValueError: If one or more variables are unset or empty, listing all
            missing names.
    """
    values = {name: os.environ.get(name) for name in var_names}
    missing = [name for name, val in values.items() if not val]
    if missing:
        raise ValueError(
            f"Missing required environment variables: {', '.join(missing)}"
        )
    return values  # type: ignore[return-value]
