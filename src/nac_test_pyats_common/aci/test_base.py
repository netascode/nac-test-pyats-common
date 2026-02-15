# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""APIC-specific base test class for ACI API testing.

This module provides the APICTestBase class, which extends the generic NACTestBase
to add ACI-specific functionality for testing APIC controllers. It handles
authentication, client management, and provides a standardized interface for
running asynchronous verification tests against ACI fabrics.

The class integrates with PyATS/Genie test frameworks and provides automatic
API call tracking for enhanced HTML reporting.
"""

import asyncio
from typing import Any

import httpx
from nac_test.pyats_core.common.base_test import NACTestBase
from pyats import aetest

from nac_test_pyats_common.common import AUTH_FAILED_MESSAGE_TEMPLATE

from .auth import APICAuth
from .defaults_resolver import (
    DEFAULT_APIC_PREFIX,
    DEFAULT_MISSING_ERROR,
    ensure_defaults_block_exists,
)
from .defaults_resolver import get_default_value as _resolve_default_value


class APICTestBase(NACTestBase):  # type: ignore[misc]
    """Base class for APIC API tests with enhanced reporting.

    This class extends the generic NACTestBase to provide APIC-specific
    functionality including APIC authentication token management, API call
    tracking for HTML reports, and wrapped HTTP client for automatic response
    capture. It serves as the foundation for all ACI-specific test classes.

    Attributes:
        token (str | None): APIC authentication token obtained during setup.
            None until successful authentication, or reset to None on auth failure.
        client (httpx.AsyncClient | None): Wrapped async HTTP client configured
            for APIC. Initialized to None, set during run_async_verification_test().
        controller_url (str): Base URL of the APIC controller (inherited).
        username (str): APIC username for authentication (inherited).
        password (str): APIC password for authentication (inherited).

    Methods:
        setup(): Initialize APIC authentication and client.
        get_apic_client(): Create and configure an APIC-specific HTTP client.
        run_async_verification_test(): Execute async verification tests with PyATS.

    Example:
        class MyAPICTest(APICTestBase):
            async def get_items_to_verify(self):
                return ['tenant1', 'tenant2']

            async def verify_item(self, item):
                # Custom verification logic here
                pass

            @aetest.test
            def verify_tenants(self, steps):
                self.run_async_verification_test(steps)
    """

    client: httpx.AsyncClient | None = None  # MUST declare at class level
    token: str | None = None  # MUST declare at class level for cleanup safety

    def _ensure_defaults_block_exists(self) -> None:
        """Validate that the defaults block exists in the data model.

        Raises:
            ValueError: If the defaults.apic block is missing from the data model,
                indicating the defaults file was not passed to nac-test.
        """
        ensure_defaults_block_exists(
            self.data_model, DEFAULT_APIC_PREFIX, DEFAULT_MISSING_ERROR
        )

    def get_default_value(self, *default_paths: str, required: bool = True) -> Any:
        """Read default value(s) from the defaults block in the merged data model.

        ACI as Code provides a defaults file (defaults.nac.yaml) that gets merged
        into the data model as a separate 'defaults' block at the root level.

        This method supports both single-path lookups and cascade/fallback behavior
        across multiple paths. When multiple paths are provided, the first non-None
        value found is returned (cascade behavior).

        Note on Return Type:
            The return type is intentionally `Any` because JMESPath queries can return
            any type (str, int, float, bool, dict, list, None) depending on the data
            model structure. This is not a type safety failure - the return type is
            genuinely dynamic and depends on what's stored at the queried path.

            Callers typically know the expected type from context:
                default_pod: int = self.get_default_value("tenants.l3outs.nodes.pod")
                default_name: str = self.get_default_value("tenants.vrf.name")

        Args:
            *default_paths: One or more JMESPaths relative to 'defaults.apic'.
                Single path: self.get_default_value("tenants.l3outs.nodes.pod")
                Cascade: self.get_default_value("path1", "path2", "path3")
            required: If True (default), raises ValueError when no default is found.
                Set to False only for truly optional defaults.

        Returns:
            The first non-None default value found from the provided paths.
            Returns None only if required=False and no defaults exist.
            Note: When required=True (default), this method never returns None -
            it either returns a value or raises ValueError.

        Raises:
            TypeError: If no paths are provided.
            ValueError: If the defaults block is missing (defaults file not
                passed) or if none of the paths contain values (when required=True).

        Examples:
            # Single path (most common):
            default_pod = self.get_default_value("tenants.l3outs.nodes.pod")

            # Cascade - try multiple paths, return first found:
            default_pod = self.get_default_value(
                "tenants.l3outs.nodes.pod",
                "tenants.l3outs.node_profiles.nodes.pod",
            )

            # Optional - returns None instead of raising if not found:
            value = self.get_default_value("tenants.l3outs.nodes.pod", required=False)
        """
        return _resolve_default_value(
            self.data_model,
            *default_paths,
            required=required,
            defaults_prefix=DEFAULT_APIC_PREFIX,
            missing_error=DEFAULT_MISSING_ERROR,
        )

    @aetest.setup  # type: ignore[untyped-decorator]
    def setup(self) -> None:
        """Setup method that extends the generic base class setup.

        Initializes the APIC test environment by:
        1. Calling the parent class setup method
        2. Obtaining an APIC authentication token using file-based locking

        Note: Client creation is deferred to run_async_verification_test() to avoid
        macOS fork() issues with httpx/SSL. Creating httpx.AsyncClient in a forked
        process before entering an async context can cause crashes on macOS due to
        OpenSSL threading primitives that are not fork-safe.

        The authentication token is obtained through the APICAuth utility which
        manages token lifecycle and prevents duplicate authentication requests
        across parallel test execution.
        """
        super().setup()

        # Get shared APIC token using file-based locking
        # This reads from file cache - no httpx client creation here
        try:
            self.token = APICAuth.get_token(
                self.controller_url, self.username, self.password
            )
        except Exception as e:
            # Convert auth failures to FAILED (not ERRORED) - auth issues are
            # expected failure conditions, not infrastructure errors
            self.token = None  # Class-level default already handles this
            self.failed(AUTH_FAILED_MESSAGE_TEMPLATE.format(e))
            return

        # NOTE: Client creation is deferred to run_async_verification_test()
        # to avoid macOS fork() + httpx/SSL crash issues

    def get_apic_client(self) -> httpx.AsyncClient:
        """Get an httpx async client configured for APIC with response tracking.

        Creates an HTTP client specifically configured for APIC API communication
        with authentication headers, base URL, and automatic response tracking
        for HTML report generation. The client is wrapped to capture all API
        interactions for detailed test reporting.

        Returns:
            httpx.AsyncClient: Configured client with APIC authentication, base URL,
                and wrapped for automatic API call tracking. The client has SSL
                verification disabled for lab environment compatibility.

        Note:
            SSL verification is disabled (verify=False) to support lab environments
            with self-signed certificates. For production environments, consider
            enabling SSL verification with proper certificate management.
        """
        headers = {"Cookie": f"APIC-cookie={self.token}"}
        # SSL verification disabled for lab environment compatibility
        client = self.pool.get_client(
            base_url=self.controller_url, headers=headers, verify=False
        )

        # Use the generic tracking wrapper from base class
        return self.wrap_client_for_tracking(client, device_name="APIC")  # type: ignore[no-any-return]

    def run_async_verification_test(self, steps: Any) -> None:
        """Execute asynchronous verification tests with PyATS step tracking.

        Simple entry point that uses base class orchestration to run async
        verification tests. This thin wrapper:
        1. Creates and manages an event loop for async operations
        2. Creates the APIC client (deferred from setup for fork safety)
        3. Calls NACTestBase.run_verification_async() to execute tests
        4. Passes results to NACTestBase.process_results_smart() for reporting
        5. Ensures proper cleanup of async resources

        The actual verification logic is handled by:
        - get_items_to_verify() - must be implemented by the test class
        - verify_item() - must be implemented by the test class

        Args:
            steps: PyATS steps object for test reporting and step management.
                Each verification item will be executed as a separate step
                with automatic pass/fail tracking.

        Note:
            This method creates its own event loop to ensure compatibility
            with PyATS synchronous test execution model. The loop and client
            connections are properly closed after test completion.

            Client creation is done HERE (not in setup) to avoid macOS fork()
            issues with httpx/SSL. Creating httpx.AsyncClient after fork() but
            before entering an async context can crash on macOS.
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            # Create client INSIDE the event loop context to avoid macOS fork+SSL crash
            self.client = self.get_apic_client()

            # Call the base class generic orchestration
            results = loop.run_until_complete(self.run_verification_async())

            # Process results using smart configuration-driven processing
            self.process_results_smart(results, steps)
        finally:
            # Clean up the APIC client connection
            if self.client is not None:  # MANDATORY: never use hasattr()
                loop.run_until_complete(self.client.aclose())
            loop.close()
