# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for IOSXETestBase helper methods."""

from nac_test_pyats_common.iosxe.test_base import IOSXETestBase


def test_excluded_features_empty_when_no_device_tags() -> None:
    """Config group without device_tags returns an empty exclusion set."""
    router = {"topology_label": "primary"}
    config_group = {"name": "cg1"}

    assert IOSXETestBase.get_excluded_features(router, config_group) == set()


def test_excluded_features_uses_topology_label_when_present() -> None:
    """SD-WAN 20.18+: topology_label selects which device_tag is 'this' router."""
    router = {"topology_label": "primary", "tags": ["legacy-tag"]}
    config_group = {
        "name": "cg1",
        "device_tags": [
            {"name": "primary", "features": ["bgp_a", "ospf_a"]},
            {"name": "secondary", "features": ["bgp_b", "ospf_b"]},
        ],
    }

    assert IOSXETestBase.get_excluded_features(router, config_group) == {
        "bgp_b",
        "ospf_b",
    }


def test_excluded_features_falls_back_to_tags_when_no_topology_label() -> None:
    """SD-WAN 20.15 and earlier: tags select which device_tag is 'this' router."""
    router = {"tags": ["secondary"]}
    config_group = {
        "name": "cg1",
        "device_tags": [
            {"name": "primary", "features": ["bgp_a"]},
            {"name": "secondary", "features": ["bgp_b"]},
        ],
    }

    assert IOSXETestBase.get_excluded_features(router, config_group) == {"bgp_a"}


def test_excluded_features_returns_empty_when_router_has_no_metadata() -> None:
    """Router missing both topology_label and tags falls through to empty set."""
    router = {"chassis_id": "C1234"}
    config_group = {
        "name": "cg1",
        "device_tags": [
            {"name": "primary", "features": ["bgp_a"]},
        ],
    }

    assert IOSXETestBase.get_excluded_features(router, config_group) == set()


def test_excluded_features_handles_missing_features_list() -> None:
    """Device tags with absent or null 'features' do not break the set comprehension."""
    router = {"topology_label": "primary"}
    config_group = {
        "name": "cg1",
        "device_tags": [
            {"name": "primary"},  # no features key
            {"name": "secondary", "features": None},
        ],
    }

    assert IOSXETestBase.get_excluded_features(router, config_group) == set()
