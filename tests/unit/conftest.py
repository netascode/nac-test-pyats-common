# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Shared fixtures for unit tests."""

import os
from collections.abc import Callable

import pytest
from _pytest.monkeypatch import MonkeyPatch
from nac_test.core.constants import ENV_CONTROLLER_CONTEXT
from nac_test.core.controller import resolve_controller
from nac_test.core.types import ControllerContext
from pyats import aetest  # type: ignore[import-untyped]

CONTROLLER_ENV_PREFIXES = (
    "ACI_",
    "SDWAN_",
    "CC_",
    "MERAKI_",
    "FMC_",
    "ISE_",
    "IOSXE_",
    "NXOS_",
)


@pytest.fixture(autouse=True)
def clean_controller_env(monkeypatch: MonkeyPatch) -> None:
    """Clear all controller-related environment variables.

    Ensures tests run in isolation regardless of the caller's shell environment.
    """
    for key in list(os.environ.keys()):
        if any(key.startswith(prefix) for prefix in CONTROLLER_ENV_PREFIXES):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv(ENV_CONTROLLER_CONTEXT, raising=False)


def resolve_and_inject_context(monkeypatch: MonkeyPatch) -> ControllerContext:
    """Resolve controller from current environment and inject into ENV_CONTROLLER_CONTEXT.

    Designed for happy-path tests to avoid DRY repetition.
    """
    ctx = resolve_controller()
    monkeypatch.setenv(ENV_CONTROLLER_CONTEXT, ctx.to_json())
    return ctx


def inject_context(monkeypatch: MonkeyPatch, ctx: ControllerContext) -> None:
    """Inject a pre-built ControllerContext into ENV_CONTROLLER_CONTEXT."""
    monkeypatch.setenv(ENV_CONTROLLER_CONTEXT, ctx.to_json())


@pytest.fixture
def make_pyats_instance() -> Callable[[type[aetest.Testcase]], aetest.Testcase]:
    """Factory fixture that instantiates a NACTestBase subclass for testing.

    pyATS aetest.Testcase subclasses need at least one @aetest.test method to
    be instantiable, so this wraps the given base class in a throwaway
    subclass rather than requiring every test module to define its own.
    """

    def _make(base_cls: type[aetest.Testcase]) -> aetest.Testcase:
        class TestClass(base_cls):  # type: ignore[misc, valid-type]
            @aetest.test
            def test_method(self) -> None:
                pass

        return TestClass()

    return _make
