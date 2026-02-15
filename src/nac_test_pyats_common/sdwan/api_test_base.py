# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""SDWAN Manager-specific base test class for SD-WAN API testing.

This module provides the SDWANManagerTestBase class, which extends the generic
NACTestBase to add SDWAN Manager-specific functionality for testing SD-WAN
controllers. It handles session management (JSESSIONID and XSRF token), client
configuration, and provides a standardized interface for running asynchronous
verification tests against SDWAN Manager.

The class integrates with PyATS/Genie test frameworks and provides automatic
API call tracking for enhanced HTML reporting.
"""

import asyncio
from typing import Any

import httpx
from nac_test.pyats_core.common.base_test import NACTestBase
from pyats import aetest

from nac_test_pyats_common.common import AUTH_FAILED_MESSAGE_TEMPLATE

from .auth import SDWANManagerAuth


class SDWANManagerTestBase(NACTestBase):  # type: ignore[misc]
    """Base class for SDWAN Manager API tests with enhanced reporting.

    This class extends the generic NACTestBase to provide SDWAN Manager-specific
    functionality including session management (JSESSIONID and optional XSRF token),
    API call tracking for HTML reports, and wrapped HTTP client for automatic
    response capture. It serves as the foundation for all SD-WAN controller-specific
    API test classes.

    The class follows the same pattern as APICTestBase for consistency across
    NAC architecture adapters. Token refresh is handled automatically by the
    AuthCache TTL mechanism.

    Attributes:
        auth_data (dict): SDWAN Manager authentication data containing jsessionid and
            optional xsrf_token obtained during setup.
        client (httpx.AsyncClient | None): Wrapped async HTTP client configured for
            SDWAN Manager. Initialized to None, set during setup().
        controller_url (str): Base URL of the SDWAN Manager (inherited).
        username (str): SDWAN Manager username for authentication (inherited).
        password (str): SDWAN Manager password for authentication (inherited).

    Methods:
        setup(): Initialize SDWAN Manager authentication and client.
        get_sdwan_manager_client(): Create and configure an SDWAN Manager-specific
            HTTP client.
        run_async_verification_test(): Execute async verification tests with PyATS.

    Example:
        class MySDWANManagerTest(SDWANManagerTestBase):
            async def get_items_to_verify(self):
                return ['device1', 'device2']

            async def verify_item(self, item):
                # Custom verification logic here
                pass

            @aetest.test
            def verify_devices(self, steps):
                self.run_async_verification_test(steps)
    """

    client: httpx.AsyncClient | None = None  # MUST declare at class level
    auth_data: dict[str, Any]  # Declared at class level for type checker compatibility

    @aetest.setup  # type: ignore[untyped-decorator]
    def setup(self) -> None:
        """Setup method that extends the generic base class setup.

        Initializes the SDWAN Manager test environment by:
        1. Calling the parent class setup method
        2. Obtaining SDWAN Manager session data (jsessionid, xsrf_token) using
           cached auth

        Note: Client creation is deferred to run_async_verification_test() to avoid
        macOS fork() issues with httpx/SSL. Creating httpx.AsyncClient in a forked
        process before entering an async context can cause crashes on macOS due to
        OpenSSL threading primitives that are not fork-safe.

        The session data is obtained through the SDWANManagerAuth utility which
        manages session lifecycle and prevents duplicate authentication requests
        across parallel test execution.
        """
        super().setup()

        # Get shared SDWAN Manager auth data (jsessionid, xsrf_token)
        # This reads from file cache - no httpx client creation here
        try:
            self.auth_data = SDWANManagerAuth.get_auth()
        except Exception as e:
            # Convert auth failures to FAILED (not ERRORED) - auth issues are
            # expected failure conditions, not infrastructure errors
            self.auth_data = {}  # Ensure attribute exists for cleanup code
            self.failed(AUTH_FAILED_MESSAGE_TEMPLATE.format(e))
            return

        # NOTE: Client creation is deferred to run_async_verification_test()
        # to avoid macOS fork() + httpx/SSL crash issues

    def get_sdwan_manager_client(self) -> httpx.AsyncClient:
        """Get an httpx async client configured for SDWAN Manager.

        Configured with response tracking.

        Creates an HTTP client specifically configured for SDWAN Manager API
        communication with session headers, base URL, and automatic response
        tracking for HTML report generation. The client is wrapped to capture all
        API interactions for detailed test reporting.

        The client includes:
        - JSESSIONID cookie in all requests (via Cookie header)
        - X-XSRF-TOKEN header when available (19.2+)
        - Content-Type: application/json header
        - Automatic API call tracking for reporting

        Returns:
            httpx.AsyncClient: Configured client with SDWAN Manager session data,
                base URL, and wrapped for automatic API call tracking. The client
                has SSL verification disabled for lab environment compatibility.

        Note:
            SSL verification is disabled (verify=False) to support lab environments
            with self-signed certificates. For production environments, consider
            enabling SSL verification with proper certificate management.
        """
        # Build headers with Cookie header (following APIC pattern for consistency)
        headers = {
            "Cookie": f"JSESSIONID={self.auth_data['jsessionid']}",
            "Content-Type": "application/json",
        }

        # Add XSRF token if available (19.2+ requires this for CSRF protection)
        if self.auth_data.get("xsrf_token"):
            headers["X-XSRF-TOKEN"] = self.auth_data["xsrf_token"]

        # Get base client from pool with SSL verification disabled for lab compatibility
        base_client = self.pool.get_client(
            base_url=self.controller_url, headers=headers, verify=False
        )

        # Use the generic tracking wrapper from base class
        return self.wrap_client_for_tracking(base_client, device_name="SDWAN Manager")  # type: ignore[no-any-return]

    def run_async_verification_test(self, steps: Any) -> None:
        """Execute asynchronous verification tests with PyATS step tracking.

        Simple entry point that uses base class orchestration to run async
        verification tests. This thin wrapper:
        1. Creates and manages an event loop for async operations
        2. Creates the SDWAN Manager client (deferred from setup for fork safety)
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
            self.client = self.get_sdwan_manager_client()

            # Call the base class generic orchestration
            results = loop.run_until_complete(self.run_verification_async())

            # Process results using smart configuration-driven processing
            self.process_results_smart(results, steps)
        finally:
            # Clean up the SDWAN Manager client connection
            if self.client is not None:  # MANDATORY: never use hasattr()
                loop.run_until_complete(self.client.aclose())
            loop.close()
