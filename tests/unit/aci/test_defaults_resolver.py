# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for defaults_resolver module.

This module tests the standalone get_default_value() and ensure_defaults_block_exists()
functions which provide defaults resolution for ACI data models.

These tests exercise the actual business logic directly without any PyATS dependencies,
providing fast, isolated unit tests for:
- Single-path default lookups
- Cascade/fallback behavior across multiple paths
- Required vs optional default handling
- Clear error messages for debugging

Note:
    The defaults_resolver module itself has NO PyATS dependencies, but importing
    it through the nac_test_pyats_common package triggers __init__.py files that
    do have such dependencies. We mock only the nac_test package import to allow
    isolated testing of the pure defaults resolution logic.
"""

import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

# Mock nac_test and pyats packages to prevent import errors from sibling modules
# The defaults_resolver module itself has no nac_test dependencies, but the
# package __init__.py files import other modules that do.
_nac_test_mock = MagicMock()
_pyats_mock = MagicMock()

# nac_test package hierarchy
sys.modules["nac_test"] = _nac_test_mock
sys.modules["nac_test.pyats_core"] = _nac_test_mock.pyats_core
sys.modules["nac_test.pyats_core.common"] = _nac_test_mock.pyats_core.common
sys.modules["nac_test.pyats_core.common.auth_cache"] = (
    _nac_test_mock.pyats_core.common.auth_cache
)
sys.modules["nac_test.pyats_core.common.base_test"] = (
    _nac_test_mock.pyats_core.common.base_test
)
sys.modules["nac_test.pyats_core.common.subprocess_auth"] = (
    _nac_test_mock.pyats_core.common.subprocess_auth
)
sys.modules["nac_test.pyats_core.common.ssh_base_test"] = (
    _nac_test_mock.pyats_core.common.ssh_base_test
)
sys.modules["nac_test.utils"] = _nac_test_mock.utils
sys.modules["nac_test.utils.controller"] = _nac_test_mock.utils.controller

# pyats package hierarchy
sys.modules["pyats"] = _pyats_mock
sys.modules["pyats.aetest"] = _pyats_mock.aetest

# Import must occur AFTER sys.modules mocking to prevent import errors
from nac_test_pyats_common.aci.defaults_resolver import (  # noqa: E402
    ensure_defaults_block_exists,
    get_default_value,
)


class TestEnsureDefaultsBlockExists:
    """Tests for ensure_defaults_block_exists() function."""

    def test_valid_defaults_block_passes(self) -> None:
        """Test that valid defaults block passes validation."""
        data_model = {"defaults": {"apic": {"key": "value"}}}
        # Should not raise
        ensure_defaults_block_exists(data_model)

    def test_missing_defaults_raises_value_error(self) -> None:
        """Test that missing defaults block raises ValueError."""
        data_model: dict[str, Any] = {"apic": {}}
        with pytest.raises(ValueError) as exc_info:
            ensure_defaults_block_exists(data_model)
        assert "Defaults block not found" in str(exc_info.value)

    def test_missing_apic_block_raises_value_error(self) -> None:
        """Test that missing apic block under defaults raises ValueError."""
        data_model: dict[str, Any] = {"defaults": {"other": {}}}
        with pytest.raises(ValueError) as exc_info:
            ensure_defaults_block_exists(data_model)
        assert "Defaults block not found" in str(exc_info.value)


class TestGetDefaultValueSinglePath:
    """Test single-path default value lookups."""

    def test_single_path_value_found(self) -> None:
        """Test that a single path lookup returns the correct value."""
        data_model = {
            "defaults": {"apic": {"tenants": {"l3outs": {"nodes": {"pod": 1}}}}}
        }

        result = get_default_value(data_model, "tenants.l3outs.nodes.pod")

        assert result == 1

    def test_single_path_missing_required_raises(self) -> None:
        """Test that missing required single path raises ValueError."""
        data_model: dict[str, Any] = {
            "defaults": {
                "apic": {}  # Empty - path doesn't exist
            }
        }

        with pytest.raises(ValueError) as exc_info:
            get_default_value(data_model, "tenants.l3outs.nodes.pod")

        error_msg = str(exc_info.value)
        # Verify single-path error message format includes full path
        assert "defaults.apic.tenants.l3outs.nodes.pod" in error_msg
        # Should NOT say "X paths" for single path
        assert "paths:" not in error_msg.lower()

    def test_single_path_missing_optional_returns_none(self) -> None:
        """Test that missing optional single path returns None."""
        data_model: dict[str, Any] = {"defaults": {"apic": {}}}

        result = get_default_value(
            data_model, "tenants.l3outs.nodes.pod", required=False
        )

        assert result is None

    def test_single_path_returns_false_value_not_none(self) -> None:
        """Test that False is returned (not treated as missing)."""
        data_model = {
            "defaults": {
                "apic": {"tenants": {"l3outs": {"bgp_peers": {"admin_state": False}}}}
            }
        }

        result = get_default_value(data_model, "tenants.l3outs.bgp_peers.admin_state")

        assert result is False  # Not None!

    def test_single_path_returns_zero_value_not_none(self) -> None:
        """Test that 0 is returned (not treated as missing)."""
        data_model = {"defaults": {"apic": {"tenants": {"priority": 0}}}}

        result = get_default_value(data_model, "tenants.priority")

        assert result == 0  # Should return 0, not None

    def test_single_path_returns_empty_string_not_none(self) -> None:
        """Test that empty string is returned (not treated as missing)."""
        data_model = {"defaults": {"apic": {"tenants": {"description": ""}}}}

        result = get_default_value(data_model, "tenants.description")

        # Note: jmespath returns "" for empty string, which is truthy check
        # but empty string is a valid value
        assert result == ""

    def test_single_path_returns_string_value(self) -> None:
        """Test that string values are returned correctly."""
        data_model = {
            "defaults": {"apic": {"tenants": {"vrf": {"name": "default-vrf"}}}}
        }

        result = get_default_value(data_model, "tenants.vrf.name")

        assert result == "default-vrf"

    def test_single_path_returns_list_value(self) -> None:
        """Test that list values are returned correctly."""
        data_model = {
            "defaults": {"apic": {"tenants": {"tags": ["production", "critical"]}}}
        }

        result = get_default_value(data_model, "tenants.tags")

        assert result == ["production", "critical"]

    def test_single_path_returns_dict_value(self) -> None:
        """Test that dict values are returned correctly."""
        data_model = {
            "defaults": {
                "apic": {"tenants": {"settings": {"key1": "value1", "key2": "value2"}}}
            }
        }

        result = get_default_value(data_model, "tenants.settings")

        assert result == {"key1": "value1", "key2": "value2"}


class TestGetDefaultValueCascade:
    """Test cascade/fallback behavior with multiple paths."""

    def test_cascade_first_path_matches(self) -> None:
        """Test that first matching path wins in cascade."""
        data_model = {
            "defaults": {
                "apic": {
                    "path1": "value1",
                    "path2": "value2",
                }
            }
        }

        result = get_default_value(data_model, "path1", "path2")

        assert result == "value1"

    def test_cascade_second_path_matches(self) -> None:
        """Test that second path is used when first is missing."""
        data_model = {
            "defaults": {
                "apic": {
                    "path2": "value2",
                }
            }
        }

        result = get_default_value(data_model, "path1", "path2")

        assert result == "value2"

    def test_cascade_third_path_matches(self) -> None:
        """Test that third path is used when first two are missing."""
        data_model = {
            "defaults": {
                "apic": {
                    "path3": "value3",
                }
            }
        }

        result = get_default_value(data_model, "path1", "path2", "path3")

        assert result == "value3"

    def test_cascade_none_match_required_raises(self) -> None:
        """Test that cascade with no matches raises ValueError."""
        data_model: dict[str, Any] = {"defaults": {"apic": {}}}

        with pytest.raises(ValueError) as exc_info:
            get_default_value(data_model, "path1", "path2", "path3")

        error_msg = str(exc_info.value)
        # Verify multi-path error message format
        assert "3 paths" in error_msg
        assert "defaults.apic.path1" in error_msg
        assert "defaults.apic.path2" in error_msg
        assert "defaults.apic.path3" in error_msg

    def test_cascade_none_match_optional_returns_none(self) -> None:
        """Test that cascade with no matches returns None when optional."""
        data_model: dict[str, Any] = {"defaults": {"apic": {}}}

        result = get_default_value(data_model, "path1", "path2", required=False)

        assert result is None

    def test_cascade_two_paths_none_match_shows_count(self) -> None:
        """Test that cascade error for 2 paths shows correct count."""
        data_model: dict[str, Any] = {"defaults": {"apic": {}}}

        with pytest.raises(ValueError) as exc_info:
            get_default_value(data_model, "path1", "path2")

        error_msg = str(exc_info.value)
        assert "2 paths" in error_msg

    def test_cascade_stops_at_first_non_none(self) -> None:
        """Test that cascade stops searching after finding non-None."""
        data_model = {
            "defaults": {
                "apic": {
                    "path1": "first_value",
                    "path2": "second_value",  # Should not be reached
                }
            }
        }

        result = get_default_value(data_model, "path1", "path2")

        assert result == "first_value"


class TestGetDefaultValueErrorHandling:
    """Test error handling scenarios."""

    def test_empty_args_raises_type_error(self) -> None:
        """Test that calling with no arguments raises TypeError."""
        data_model = {"defaults": {"apic": {"key": "value"}}}

        with pytest.raises(TypeError) as exc_info:
            get_default_value(data_model)

        error_msg = str(exc_info.value)
        assert "requires at least one path argument" in error_msg
        assert "Example:" in error_msg  # Should include helpful example

    def test_defaults_block_missing_raises(self) -> None:
        """Test that missing defaults block raises ValueError."""
        data_model: dict[str, Any] = {
            "apic": {}  # Missing 'defaults' key entirely
        }

        with pytest.raises(ValueError) as exc_info:
            get_default_value(data_model, "any.path")

        error_msg = str(exc_info.value)
        assert "Defaults block not found" in error_msg
        assert "defaults.nac.yaml" in error_msg  # Helpful guidance

    def test_defaults_apic_block_missing_raises(self) -> None:
        """Test that missing defaults.apic block raises ValueError."""
        data_model: dict[str, Any] = {
            "defaults": {
                # Missing 'apic' key
                "other": {}
            }
        }

        with pytest.raises(ValueError) as exc_info:
            get_default_value(data_model, "any.path")

        assert "Defaults block not found" in str(exc_info.value)

    def test_empty_data_model_raises(self) -> None:
        """Test that empty data model raises ValueError."""
        data_model: dict[str, Any] = {}

        with pytest.raises(ValueError) as exc_info:
            get_default_value(data_model, "any.path")

        assert "Defaults block not found" in str(exc_info.value)

    def test_error_message_includes_nac_test_example(self) -> None:
        """Test that defaults error includes nac-test command example."""
        data_model = {"something": "else"}

        with pytest.raises(ValueError) as exc_info:
            get_default_value(data_model, "any.path")

        error_msg = str(exc_info.value)
        assert "nac-test" in error_msg
        assert "-d" in error_msg  # Shows example flag


class TestGetDefaultValueNestedPaths:
    """Test deeply nested path lookups (realistic ACI scenarios)."""

    def test_deeply_nested_path(self) -> None:
        """Test lookup of deeply nested ACI default."""
        data_model = {
            "defaults": {
                "apic": {
                    "tenants": {
                        "l3outs": {
                            "node_profiles": {
                                "interface_profiles": {"interfaces": {"pod": 1}}
                            }
                        }
                    }
                }
            }
        }

        result = get_default_value(
            data_model,
            "tenants.l3outs.node_profiles.interface_profiles.interfaces.pod",
        )

        assert result == 1

    def test_realistic_cascade_scenario(self) -> None:
        """Test realistic ACI cascade - pods can be at different hierarchy levels."""
        data_model = {
            "defaults": {
                "apic": {
                    "tenants": {
                        "l3outs": {
                            "node_profiles": {
                                "nodes": {
                                    "pod": 2  # This should be found
                                }
                            }
                        }
                    }
                }
            }
        }

        # First path doesn't exist, second does
        result = get_default_value(
            data_model,
            "tenants.l3outs.nodes.pod",
            "tenants.l3outs.node_profiles.nodes.pod",
        )

        assert result == 2

    def test_bgp_peer_defaults_cascade(self) -> None:
        """Test realistic BGP peer defaults with cascade."""
        data_model = {
            "defaults": {
                "apic": {"tenants": {"l3outs": {"bgp_peers": {"remote_as": 65001}}}}
            }
        }

        # Try interface-level first, fall back to l3out-level
        result = get_default_value(
            data_model,
            "tenants.l3outs.node_profiles.interface_profiles.bgp_peers.remote_as",
            "tenants.l3outs.bgp_peers.remote_as",
        )

        assert result == 65001

    def test_interface_type_default(self) -> None:
        """Test interface type defaults."""
        data_model = {
            "defaults": {
                "apic": {
                    "tenants": {
                        "l3outs": {
                            "node_profiles": {
                                "interface_profiles": {
                                    "interfaces": {"type": "ext-svi"}
                                }
                            }
                        }
                    }
                }
            }
        }

        result = get_default_value(
            data_model,
            "tenants.l3outs.node_profiles.interface_profiles.interfaces.type",
        )

        assert result == "ext-svi"

    def test_custom_defaults_prefix(self) -> None:
        """Test using a custom defaults prefix for different controllers."""
        data_model = {
            "defaults": {"sdwan": {"feature_templates": {"name": "default-template"}}}
        }

        result = get_default_value(
            data_model,
            "feature_templates.name",
            defaults_prefix="defaults.sdwan",
        )

        assert result == "default-template"


class TestGetDefaultValuePathFormats:
    """Test various path format edge cases."""

    def test_single_key_path(self) -> None:
        """Test path with only one key."""
        data_model = {"defaults": {"apic": {"version": "5.2"}}}

        result = get_default_value(data_model, "version")

        assert result == "5.2"

    def test_two_key_path(self) -> None:
        """Test path with two keys."""
        data_model = {"defaults": {"apic": {"tenants": {"name": "default-tenant"}}}}

        result = get_default_value(data_model, "tenants.name")

        assert result == "default-tenant"

    def test_path_with_numeric_keys(self) -> None:
        """Test path traversal works with numeric string keys."""
        data_model = {"defaults": {"apic": {"pods": {"1": {"id": 1}}}}}

        # JMESPath handles string keys
        result = get_default_value(data_model, 'pods."1".id')

        assert result == 1


class TestGetDefaultValuePartialPathMatch:
    """Test behavior when path partially matches."""

    def test_partial_path_match_returns_none(self) -> None:
        """Test that partial path match does not return intermediate dict."""
        data_model: dict[str, Any] = {
            "defaults": {
                "apic": {
                    "tenants": {
                        "l3outs": {
                            # nodes key doesn't exist
                        }
                    }
                }
            }
        }

        # Path partially exists but full path doesn't
        result = get_default_value(
            data_model, "tenants.l3outs.nodes.pod", required=False
        )

        assert result is None

    def test_intermediate_dict_not_returned(self) -> None:
        """Test that asking for child of leaf returns None, not partial match."""
        data_model = {
            "defaults": {
                "apic": {
                    "tenants": {
                        "name": "tenant1"  # name is a leaf string, not a dict
                    }
                }
            }
        }

        # Try to go beyond the leaf - should return None
        result = get_default_value(data_model, "tenants.name.something", required=False)

        assert result is None
