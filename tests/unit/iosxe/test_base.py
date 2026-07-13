# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for IOSXETestBase helper methods."""

import logging

import pytest

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


def test_excluded_features_returns_empty_when_router_has_no_metadata(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Router missing both topology_label and tags returns empty set + WARNING.

    The warning is the operator-facing signal that the data model is
    mis-tagged. We assert level and identifying fields, not exact wording,
    so message rewording doesn't break the test.
    """
    router = {"chassis_id": "C1234"}
    config_group = {
        "name": "cg1",
        "device_tags": [
            {"name": "primary", "features": ["bgp_a"]},
        ],
    }

    with caplog.at_level(logging.WARNING):
        result = IOSXETestBase.get_excluded_features(router, config_group)

    assert result == set()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    rendered = warnings[0].getMessage()
    assert "cg1" in rendered
    assert "C1234" in rendered


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


def test_excluded_features_empty_when_topology_label_matches_no_device_tag(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Fail-safe: an unrecognized topology_label excludes nothing (not everything).

    A typo in ``topology_label`` (or a config-group rename) would previously
    have flagged every device_tag as 'the other device' and silently skipped
    all features. Fail-safe direction is now to log and return an empty set.
    """
    router = {"topology_label": "tertiary"}
    config_group = {
        "name": "cg1",
        "device_tags": [
            {"name": "primary", "features": ["bgp_a"]},
            {"name": "secondary", "features": ["bgp_b"]},
        ],
    }

    with caplog.at_level(logging.WARNING):
        result = IOSXETestBase.get_excluded_features(router, config_group)

    assert result == set()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "tertiary" in warnings[0].getMessage()


def test_excluded_features_empty_when_tags_match_no_device_tag(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Fail-safe applies to the UX 1.0 tags path as well."""
    router = {"tags": ["unknown"]}
    config_group = {
        "name": "cg1",
        "device_tags": [
            {"name": "primary", "features": ["bgp_a"]},
            {"name": "secondary", "features": ["bgp_b"]},
        ],
    }

    with caplog.at_level(logging.WARNING):
        result = IOSXETestBase.get_excluded_features(router, config_group)

    assert result == set()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "unknown" in warnings[0].getMessage()


def test_excluded_features_empty_string_topology_label_falls_back_to_tags() -> None:
    """Empty-string topology_label is treated as absent; UX 1.0 tags path applies.

    Prevents a partially-migrated UX 2.0 router with an empty ``topology_label``
    from silently degrading to legacy semantics without an intentional signal.
    """
    router = {"topology_label": "", "tags": ["secondary"]}
    config_group = {
        "name": "cg1",
        "device_tags": [
            {"name": "primary", "features": ["bgp_a"]},
            {"name": "secondary", "features": ["bgp_b"]},
        ],
    }

    assert IOSXETestBase.get_excluded_features(router, config_group) == {"bgp_a"}


def test_excluded_features_ignores_non_list_features_with_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A ``features`` value that is a scalar (YAML mistake) is skipped, not iterated.

    Without this guard, ``for feature in "bgp_a"`` would yield individual
    characters into the exclusion set.
    """
    router = {"topology_label": "primary"}
    config_group = {
        "name": "cg1",
        "device_tags": [
            {"name": "primary", "features": ["bgp_a"]},
            {"name": "secondary", "features": "bgp_b"},  # scalar, not list
        ],
    }

    with caplog.at_level(logging.WARNING):
        result = IOSXETestBase.get_excluded_features(router, config_group)

    assert result == set()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "secondary" in warnings[0].getMessage()
