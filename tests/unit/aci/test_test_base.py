# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for APICTestBase.setup() error handling.

This module tests the error handling behavior of the APICTestBase.setup() method,
specifically verifying that authentication failures:
1. Convert to FAILED status (not ERRORED) via self.failed()
2. Keep self.token as None (class-level default) to signal no valid token
3. Propagate exception details in the error message

These tests exercise the actual business logic for error handling without
running real authentication or API calls.

Note:
    These tests require mocking PyATS and nac_test packages. To avoid polluting
    global sys.modules, we use fixtures that save and restore module state.
"""

import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# Create a real class to use as the mock NACTestBase
class MockNACTestBase:
    """Mock base class for NACTestBase to enable proper inheritance."""

    controller_url: str
    username: str
    password: str
    data_model: dict[str, Any]
    pool: Any

    def setup(self) -> None:
        """Mock setup method."""
        pass

    def failed(self, reason: str) -> None:
        """Mock failed method."""
        pass


@pytest.fixture
def isolated_test_base_module() -> Any:
    """Fixture that imports APICTestBase with isolated sys.modules mocking.

    This fixture:
    1. Saves the current sys.modules state
    2. Adds mock entries for nac_test and pyats
    3. Imports APICTestBase
    4. Restores sys.modules on teardown

    Returns:
        The APICTestBase class from the isolated import.
    """
    # Save original sys.modules entries that we'll modify
    saved_modules: dict[str, Any] = {}
    modules_to_mock = [
        "nac_test",
        "nac_test.pyats_core",
        "nac_test.pyats_core.common",
        "nac_test.pyats_core.common.auth_cache",
        "nac_test.pyats_core.common.base_test",
        "nac_test.pyats_core.common.subprocess_auth",
        "nac_test.pyats_core.common.ssh_base_test",
        "nac_test.utils",
        "nac_test.utils.controller",
        "pyats",
        "pyats.aetest",
    ]

    # Save existing modules (if any)
    for mod_name in modules_to_mock:
        if mod_name in sys.modules:
            saved_modules[mod_name] = sys.modules[mod_name]

    # Also save the nac_test_pyats_common.aci.test_base module if it was imported
    test_base_module = "nac_test_pyats_common.aci.test_base"
    if test_base_module in sys.modules:
        saved_modules[test_base_module] = sys.modules[test_base_module]
        del sys.modules[test_base_module]

    try:
        # Create mocks
        nac_test_mock = MagicMock()
        pyats_mock = MagicMock()

        # Set up nac_test mock hierarchy
        sys.modules["nac_test"] = nac_test_mock
        sys.modules["nac_test.pyats_core"] = nac_test_mock.pyats_core
        sys.modules["nac_test.pyats_core.common"] = nac_test_mock.pyats_core.common
        sys.modules["nac_test.pyats_core.common.auth_cache"] = (
            nac_test_mock.pyats_core.common.auth_cache
        )
        sys.modules["nac_test.pyats_core.common.base_test"] = (
            nac_test_mock.pyats_core.common.base_test
        )
        sys.modules["nac_test.pyats_core.common.subprocess_auth"] = (
            nac_test_mock.pyats_core.common.subprocess_auth
        )
        sys.modules["nac_test.pyats_core.common.ssh_base_test"] = (
            nac_test_mock.pyats_core.common.ssh_base_test
        )
        sys.modules["nac_test.utils"] = nac_test_mock.utils
        sys.modules["nac_test.utils.controller"] = nac_test_mock.utils.controller

        # Set up pyats mock hierarchy
        sys.modules["pyats"] = pyats_mock
        sys.modules["pyats.aetest"] = pyats_mock.aetest

        # Configure the aetest.setup decorator to be a passthrough
        pyats_mock.aetest.setup = lambda fn: fn

        # Configure NACTestBase to use our real mock class
        nac_test_mock.pyats_core.common.base_test.NACTestBase = MockNACTestBase

        # Import APICTestBase with mocks in place
        from nac_test_pyats_common.aci.test_base import APICTestBase

        yield APICTestBase

    finally:
        # Restore original sys.modules state
        for mod_name in modules_to_mock:
            if mod_name in saved_modules:
                sys.modules[mod_name] = saved_modules[mod_name]
            elif mod_name in sys.modules:
                del sys.modules[mod_name]

        # Remove the test_base module so it can be re-imported fresh
        if test_base_module in sys.modules:
            del sys.modules[test_base_module]


class TestAPICTestBaseSetup:
    """Test setup() error handling - actual business logic."""

    def test_runtime_error_converts_to_failed_status(
        self, isolated_test_base_module: Any
    ) -> None:
        """Test that RuntimeError from APICAuth.get_token() converts to FAILED status.

        When authentication fails with a RuntimeError (e.g., subprocess failure,
        network error), the setup() method should:
        - Call self.failed() to mark the test as FAILED (not ERRORED)
        - Not raise the exception (graceful handling)
        """
        APICTestBase = isolated_test_base_module
        # Create instance using __new__ to bypass __init__
        instance = object.__new__(APICTestBase)
        instance.controller_url = "https://apic.example.com"
        instance.username = "admin"
        instance.password = "password123"
        instance.failed = MagicMock()

        with patch(
            "nac_test_pyats_common.aci.test_base.APICAuth.get_token"
        ) as mock_get_token:
            mock_get_token.side_effect = RuntimeError(
                "Authentication subprocess failed"
            )

            # Call setup() - the error should be caught and failed() called
            instance.setup()

            # Verify failed() was called (test converts to FAILED, not ERRORED)
            instance.failed.assert_called_once()
            call_args = instance.failed.call_args[0][0]
            assert "Authentication failed:" in call_args

    def test_value_error_converts_to_failed_status(
        self, isolated_test_base_module: Any
    ) -> None:
        """Test that ValueError from APICAuth.get_token() converts to FAILED status.

        When authentication fails with a ValueError (e.g., missing environment
        variables, invalid credentials format), the setup() method should:
        - Call self.failed() to mark the test as FAILED (not ERRORED)
        - Not raise the exception (graceful handling)
        """
        APICTestBase = isolated_test_base_module
        instance = object.__new__(APICTestBase)
        instance.controller_url = "https://apic.example.com"
        instance.username = "admin"
        instance.password = "password123"
        instance.failed = MagicMock()

        with patch(
            "nac_test_pyats_common.aci.test_base.APICAuth.get_token"
        ) as mock_get_token:
            mock_get_token.side_effect = ValueError(
                "Missing required environment variables: APIC_URL"
            )

            # Call setup()
            instance.setup()

            # Verify failed() was called
            instance.failed.assert_called_once()
            call_args = instance.failed.call_args[0][0]
            assert "Authentication failed:" in call_args

    def test_token_set_to_none_on_auth_failure(
        self, isolated_test_base_module: Any
    ) -> None:
        """Test that self.token remains None on auth failure.

        When authentication fails, self.token is explicitly set to None to
        clearly signal that no valid token exists. The class-level declaration
        (token: str | None = None) ensures the attribute always exists,
        preventing AttributeError in downstream code.
        """
        APICTestBase = isolated_test_base_module
        instance = object.__new__(APICTestBase)
        instance.controller_url = "https://apic.example.com"
        instance.username = "admin"
        instance.password = "password123"
        instance.failed = MagicMock()

        with patch(
            "nac_test_pyats_common.aci.test_base.APICAuth.get_token"
        ) as mock_get_token:
            mock_get_token.side_effect = RuntimeError("Connection refused")

            # Call setup()
            instance.setup()

            # Verify token is None (not empty string, not missing)
            assert instance.token is None

    def test_error_message_includes_exception_details(
        self, isolated_test_base_module: Any
    ) -> None:
        """Test that error message via self.failed() includes exception details.

        The error message passed to self.failed() should include the original
        exception message to help with debugging authentication failures.
        """
        APICTestBase = isolated_test_base_module
        instance = object.__new__(APICTestBase)
        instance.controller_url = "https://apic.example.com"
        instance.username = "admin"
        instance.password = "password123"
        instance.failed = MagicMock()

        specific_error_message = (
            "SSL certificate verification failed for apic.example.com"
        )

        with patch(
            "nac_test_pyats_common.aci.test_base.APICAuth.get_token"
        ) as mock_get_token:
            mock_get_token.side_effect = RuntimeError(specific_error_message)

            # Call setup()
            instance.setup()

            # Verify the specific error message is included
            instance.failed.assert_called_once()
            call_args = instance.failed.call_args[0][0]
            assert specific_error_message in call_args
            assert call_args == f"Authentication failed: {specific_error_message}"

    def test_runtime_error_does_not_propagate_exception(
        self, isolated_test_base_module: Any
    ) -> None:
        """Test that RuntimeError is caught and does not propagate.

        The setup() method should handle the exception gracefully and return
        normally after calling self.failed(). The test should not raise.
        """
        APICTestBase = isolated_test_base_module
        instance = object.__new__(APICTestBase)
        instance.controller_url = "https://apic.example.com"
        instance.username = "admin"
        instance.password = "password123"
        instance.failed = MagicMock()

        with patch(
            "nac_test_pyats_common.aci.test_base.APICAuth.get_token"
        ) as mock_get_token:
            mock_get_token.side_effect = RuntimeError("Network unreachable")

            # This should NOT raise - exception should be caught
            # If setup() raises, the test will fail
            instance.setup()

            # If we reach here, exception was handled correctly
            assert True

    def test_value_error_does_not_propagate_exception(
        self, isolated_test_base_module: Any
    ) -> None:
        """Test that ValueError is caught and does not propagate.

        The setup() method should handle the exception gracefully and return
        normally after calling self.failed(). The test should not raise.
        """
        APICTestBase = isolated_test_base_module
        instance = object.__new__(APICTestBase)
        instance.controller_url = "https://apic.example.com"
        instance.username = "admin"
        instance.password = "password123"
        instance.failed = MagicMock()

        with patch(
            "nac_test_pyats_common.aci.test_base.APICAuth.get_token"
        ) as mock_get_token:
            mock_get_token.side_effect = ValueError("Invalid token format")

            # This should NOT raise - exception should be caught
            # If setup() raises, the test will fail
            instance.setup()

            # If we reach here, exception was handled correctly
            assert True

    def test_unexpected_exception_converts_to_failed_status(
        self, isolated_test_base_module: Any
    ) -> None:
        """Test that unexpected exception types are also caught and convert to FAILED.

        The setup() method uses `except Exception` to catch ALL authentication
        failures, including unexpected types like ConnectionError, TimeoutError,
        OSError, etc. This prevents any auth failure from producing an ERRORED
        status (which implies infrastructure failure, not test failure).
        """
        APICTestBase = isolated_test_base_module
        instance = object.__new__(APICTestBase)
        instance.controller_url = "https://apic.example.com"
        instance.username = "admin"
        instance.password = "password123"
        instance.failed = MagicMock()

        with patch(
            "nac_test_pyats_common.aci.test_base.APICAuth.get_token"
        ) as mock_get_token:
            mock_get_token.side_effect = ConnectionError("Connection refused")

            # This should NOT raise - broad except catches all exceptions
            instance.setup()

            # Verify failed() was called with appropriate message
            instance.failed.assert_called_once()
            call_args = instance.failed.call_args[0][0]
            assert "Authentication failed:" in call_args
            assert "Connection refused" in call_args
            assert instance.token is None
