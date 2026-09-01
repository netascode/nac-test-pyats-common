# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Shared contract tests across architecture-specific TestBase classes.

Each of APICTestBase, SDWANManagerTestBase, and CatalystCenterTestBase guards
its setup() with an identical controller_type mismatch check. This module
covers that behavior once for all three, instead of duplicating it per
architecture test module.
"""

from collections.abc import Callable
from unittest.mock import patch

import pytest
from nac_test.core.types import ControllerContext
from pyats import aetest  # type: ignore[import-untyped]
from pyats.aetest.signals import AEtestFailedSignal

from nac_test_pyats_common.aci.test_base import APICTestBase
from nac_test_pyats_common.catc.api_test_base import CatalystCenterTestBase
from nac_test_pyats_common.sdwan.api_test_base import SDWANManagerTestBase


@pytest.mark.parametrize(
    ("test_base_cls", "expected_controller_type", "env", "resolved_controller_type"),
    [
        (
            APICTestBase,
            "ACI",
            {
                "SDWAN_URL": "https://sdwan.example.com",
                "SDWAN_USERNAME": "admin",
                "SDWAN_PASSWORD": "password",
            },
            "SDWAN",
        ),
        (
            SDWANManagerTestBase,
            "SDWAN",
            {
                "ACI_URL": "https://apic.example.com",
                "ACI_USERNAME": "admin",
                "ACI_PASSWORD": "password",
            },
            "ACI",
        ),
        (
            CatalystCenterTestBase,
            "CC",
            {
                "ACI_URL": "https://apic.example.com",
                "ACI_USERNAME": "admin",
                "ACI_PASSWORD": "password",
            },
            "ACI",
        ),
    ],
    ids=["aci", "sdwan", "catc"],
)
def test_setup_fails_on_controller_type_mismatch(
    test_base_cls: type[aetest.Testcase],
    expected_controller_type: str,
    env: dict[str, str],
    resolved_controller_type: str,
    make_pyats_instance: Callable[[type], aetest.Testcase],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """setup() fails when nac-test resolved a different controller_type."""
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    test_instance = make_pyats_instance(test_base_cls)

    with patch.object(test_instance, "load_data_model", return_value={"test": "data"}):
        with pytest.raises(AEtestFailedSignal) as exc_info:
            test_instance.setup()

    assert f"controller_type={expected_controller_type}" in str(exc_info.value)
    assert resolved_controller_type in str(exc_info.value)


@pytest.mark.parametrize(
    (
        "test_base_cls",
        "expected_controller_type",
        "context_controller_type",
        "cred_env",
    ),
    [
        (
            APICTestBase,
            "ACI",
            "SDWAN",
            {
                "SDWAN_URL": "https://sdwan.example.com",
                "SDWAN_USERNAME": "admin",
                "SDWAN_PASSWORD": "password",
            },
        ),
        (
            SDWANManagerTestBase,
            "SDWAN",
            "ACI",
            {
                "ACI_URL": "https://apic.example.com",
                "ACI_USERNAME": "admin",
                "ACI_PASSWORD": "password",
            },
        ),
        (
            CatalystCenterTestBase,
            "CC",
            "ACI",
            {
                "ACI_URL": "https://apic.example.com",
                "ACI_USERNAME": "admin",
                "ACI_PASSWORD": "password",
            },
        ),
    ],
    ids=["aci", "sdwan", "catc"],
)
def test_setup_fails_on_controller_type_mismatch_via_context(
    test_base_cls: type[aetest.Testcase],
    expected_controller_type: str,
    context_controller_type: str,
    cred_env: dict[str, str],
    make_pyats_instance: Callable[[type], aetest.Testcase],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """setup() fails when NAC_TEST_CONTROLLER_CONTEXT has mismatched controller_type.

    This test uses the primary controller detection path (NAC_TEST_CONTROLLER_CONTEXT)
    instead of relying on fallback detection from legacy env vars. This ensures tests
    remain valid when Phase 3 removes the fallback logic.
    """
    # Set controller context to a different controller type
    ctx = ControllerContext(
        controller_type=context_controller_type, auth_method="session"
    )
    monkeypatch.setenv("NAC_TEST_CONTROLLER_CONTEXT", ctx.to_json())

    # Still need credential env vars for get_connection_params()
    for key, value in cred_env.items():
        monkeypatch.setenv(key, value)

    test_instance = make_pyats_instance(test_base_cls)

    with patch.object(test_instance, "load_data_model", return_value={"test": "data"}):
        with pytest.raises(AEtestFailedSignal) as exc_info:
            test_instance.setup()

    assert f"controller_type={expected_controller_type}" in str(exc_info.value)
    assert context_controller_type in str(exc_info.value)


@pytest.mark.parametrize(
    ("test_base_cls", "controller_type", "unsupported_auth_method"),
    [
        (APICTestBase, "ACI", "token"),
        (CatalystCenterTestBase, "CC", "token"),
    ],
    ids=["aci", "catc"],
)
def test_setup_fails_on_unsupported_auth_method(
    test_base_cls: type[aetest.Testcase],
    controller_type: str,
    unsupported_auth_method: str,
    make_pyats_instance: Callable[[type], aetest.Testcase],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """setup() fails when auth_method is not in _SUPPORTED_AUTH_METHODS."""
    ctx = ControllerContext(
        controller_type=controller_type,
        auth_method=unsupported_auth_method,
    )
    monkeypatch.setenv("NAC_TEST_CONTROLLER_CONTEXT", ctx.to_json())

    # Provide URL env var so get_controller_url() succeeds in the parent
    monkeypatch.setenv(f"{controller_type}_URL", "https://example.com")

    test_instance = make_pyats_instance(test_base_cls)

    # Mock get_connection_params since the unsupported auth_method may not
    # exist in the controller registry — we're testing the subclass guard
    dummy_params = {
        "username": "admin",
        "password": "pass",
        "token": "tok",
    }
    with (
        patch.object(
            test_instance,
            "load_data_model",
            return_value={"test": "data"},
        ),
        patch(
            "nac_test.pyats_core.common.base_test.get_connection_params",
            return_value=dummy_params,
        ),
    ):
        with pytest.raises(AEtestFailedSignal) as exc_info:
            test_instance.setup()

    # Verify we hit the auth_method guard (not a network error whose message
    # might accidentally contain the auth method string, e.g. "/auth/token")
    assert "supports auth_methods" in str(exc_info.value)
    assert unsupported_auth_method in str(exc_info.value)
