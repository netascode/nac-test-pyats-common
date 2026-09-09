# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Shared fixtures for unit tests."""

import os
from collections.abc import Callable

import pytest
from _pytest.monkeypatch import MonkeyPatch
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
