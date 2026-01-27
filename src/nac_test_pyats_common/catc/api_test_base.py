# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Catalyst Center-specific base test class for API testing.

This module provides the CatalystCenterTestBase class, which extends the generic
NACTestBase to add Catalyst Center-specific functionality for testing enterprise
network controllers. It handles token-based authentication, client configuration,
and provides a standardized interface for running asynchronous verification tests.

The class integrates with PyATS/Genie test frameworks and provides automatic
API call tracking for enhanced HTML reporting.
"""

import asyncio
import os
from typing import Any

import httpx
from nac_test.pyats_core.common.base_test import (
    NACTestBase,  # type: ignore[import-untyped]
)
from pyats import aetest  # type: ignore[import-untyped]

from .auth import CatalystCenterAuth


class CatalystCenterTestBase(NACTestBase):  # type: ignore[misc]
    """Base class for Catalyst Center API tests with enhanced reporting.

    This class extends the generic NACTestBase to provide Catalyst Center-specific
    functionality including token-based authentication (X-Auth-Token header),
    API call tracking for HTML reports, and wrapped HTTP client for automatic
    response capture. It serves as the foundation for all Catalyst Center-specific
    API test classes.

    The class follows the same pattern as APICTestBase and VManageTestBase for
    consistency across NAC architecture adapters. Token refresh is handled
    automatically by the AuthCache TTL mechanism.

    Attributes:
        auth_data (dict): Catalyst Center authentication data containing the
            token obtained during setup.
        client (httpx.AsyncClient): Wrapped async HTTP client configured for
            Catalyst Center.
        controller_url (str): Base URL of the Catalyst Center controller.
        verify_ssl (bool): Whether SSL verification is enabled.

    Methods:
        setup(): Initialize Catalyst Center authentication and client.
        get_catc_client(): Create and configure a Catalyst Center-specific HTTP client.
        run_async_verification_test(): Execute async verification tests with PyATS.

    Example:
        class MyDeviceTest(CatalystCenterTestBase):
            async def get_items_to_verify(self):
                return ['device1', 'device2']

            async def verify_item(self, item):
                response = await self.client.get(
                    f"/dna/intent/api/v1/network-device/{item}"
                )
                return response.status_code == 200

            @aetest.test
            def verify_devices(self, steps):
                self.run_async_verification_test(steps)
    """

    @aetest.setup  # type: ignore[misc, untyped-decorator]
    def setup(self) -> None:
        """Setup method that extends the generic base class setup.

        Initializes the Catalyst Center test environment by:
        1. Calling the parent class setup method
        2. Obtaining Catalyst Center authentication token using cached auth
        3. Configuring SSL verification from environment
        4. Creating and storing a Catalyst Center client for use in verification methods

        The authentication token is obtained through the CatalystCenterAuth utility
        which manages token lifecycle and prevents duplicate authentication requests
        across parallel test execution.
        """
        super().setup()

        # Get Catalyst Center auth data (token)
        self.auth_data = CatalystCenterAuth.get_auth()

        # Get controller URL from environment
        self.controller_url = os.environ.get("CC_URL", "").rstrip("/")

        # Determine SSL verification setting
        insecure = os.environ.get("CC_INSECURE", "True").lower() in ("true", "1", "yes")
        self.verify_ssl = not insecure

        # Store the Catalyst Center client for use in verification methods
        self.client = self.get_catc_client()

    def get_catc_client(self) -> httpx.AsyncClient:
        """Get an httpx async client configured for Catalyst Center.

        Configured with response tracking.

        Creates an HTTP client specifically configured for Catalyst Center API
        communication with authentication headers, base URL, and automatic response
        tracking for HTML report generation. The client is wrapped to capture all
        API interactions for detailed test reporting.

        The client includes:
        - X-Auth-Token header for authentication
        - Content-Type: application/json header
        - Accept: application/json header
        - Automatic API call tracking for reporting

        Returns:
            httpx.AsyncClient: Configured client with Catalyst Center authentication,
                base URL, and wrapped for automatic API call tracking. SSL verification
                is controlled by the CC_INSECURE environment variable.

        Note:
            SSL verification can be disabled via CC_INSECURE=True to support lab
            environments with self-signed certificates. For production environments,
            consider enabling SSL verification with proper certificate management.
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Auth-Token": self.auth_data["token"],
        }

        # Get base client from pool with SSL verification setting
        base_client = self.pool.get_client(
            base_url=self.controller_url,
            headers=headers,
            verify=self.verify_ssl,
        )

        # Use the generic tracking wrapper from base class
        return self.wrap_client_for_tracking(base_client, device_name="CatalystCenter")  # type: ignore[no-any-return]

    def run_async_verification_test(self, steps: Any) -> None:
        """Execute asynchronous verification tests with PyATS step tracking.

        Simple entry point that uses base class orchestration to run async
        verification tests. This thin wrapper:
        1. Creates and manages an event loop for async operations
        2. Calls NACTestBase.run_verification_async() to execute tests
        3. Passes results to NACTestBase.process_results_smart() for reporting
        4. Ensures proper cleanup of async resources

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
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            # Call the base class generic orchestration
            results = loop.run_until_complete(self.run_verification_async())

            # Process results using smart configuration-driven processing
            self.process_results_smart(results, steps)
        finally:
            # Clean up the Catalyst Center client connection
            if hasattr(self, "client"):
                loop.run_until_complete(self.client.aclose())
            loop.close()
