# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

# SPDX-License-Identifier: MPL-2.0

"""FMC-specific base test class for API testing.

This module provides the FMCTestBase class, which extends the generic NACTestBase
to add FMC-specific functionality for testing Firepower Management Center
controllers. It handles token-based authentication, client configuration,
and provides a standardized interface for running asynchronous verification tests.

The class integrates with PyATS/Genie test frameworks and provides automatic
API call tracking for enhanced HTML reporting.
"""

import asyncio
from typing import Any

import httpx
from nac_test.pyats_core.common.base_test import (
    NACTestBase,  # type: ignore[import-untyped]
)
from pyats import aetest  # type: ignore[import-untyped]

from .auth import FMCAuth


class FMCTestBase(NACTestBase):  # type: ignore[misc]
    """Base class for FMC API tests with enhanced reporting.

    This class extends the generic NACTestBase to provide FMC-specific
    functionality including token-based authentication (X-auth-access-token
    header), domain-scoped API paths, API call tracking for HTML reports,
    and wrapped HTTP client for automatic response capture.

    The class follows the same pattern as APICTestBase and SDWANManagerTestBase
    for consistency across NAC architecture adapters.

    Attributes:
        auth_data (dict): FMC authentication data containing the access token
            and domain UUID obtained during setup.
        domain_uuid (str): FMC domain UUID for API path construction.
        client (httpx.AsyncClient | None): Wrapped async HTTP client configured
            for FMC. Initialized to None, set during run_async_verification_test().
        controller_url (str): Base URL of the FMC controller (inherited).

    Example:
        class MyFMCTest(FMCTestBase):
            async def get_items_to_verify(self):
                return [{'device_id': 'abc123'}, {'device_id': 'def456'}]

            async def verify_item(self, semaphore, client, context):
                # Custom verification logic querying FMC API
                pass

            @aetest.test
            def verify_devices(self, steps):
                self.run_async_verification_test(steps)
    """

    client: httpx.AsyncClient | None = None
    auth_data: dict[str, Any]
    domain_uuid: str

    @aetest.setup  # type: ignore[misc, untyped-decorator]
    def setup(self) -> None:
        """Setup method that extends the generic base class setup.

        Initializes the FMC test environment by:
        1. Calling the parent class setup method
        2. Obtaining FMC authentication token and domain UUID

        Note: Client creation is deferred to run_async_verification_test() to avoid
        macOS fork() issues with httpx/SSL.
        """
        super().setup()

        try:
            self.auth_data = FMCAuth.get_auth()
            self.domain_uuid = self.auth_data.get("domain_uuid", "")
        except (RuntimeError, ValueError) as e:
            self.auth_data = {}
            self.domain_uuid = ""
            self.failed(f"Authentication failed: {e}")
            return

    def get_fmc_client(self) -> httpx.AsyncClient:
        """Get an httpx async client configured for FMC with response tracking.

        Creates an HTTP client configured for FMC API communication with
        authentication headers, domain-scoped base URL, and automatic response
        tracking for HTML report generation.

        Returns:
            httpx.AsyncClient configured with FMC authentication and base URL,
            wrapped for automatic API call tracking.
        """
        base_url = self.controller_url.rstrip("/")
        if self.domain_uuid:
            base_url = f"{base_url}/api/fmc_config/v1/domain/{self.domain_uuid}"
        else:
            base_url = f"{base_url}/api/fmc_config/v1"

        headers = {
            "X-auth-access-token": self.auth_data["access_token"],
            "Content-Type": "application/json",
        }

        client = self.pool.get_client(base_url=base_url, headers=headers, verify=False)

        return self.wrap_client_for_tracking(client, device_name="FMC")  # type: ignore[no-any-return]

    def run_async_verification_test(self, steps: Any) -> None:
        """Execute asynchronous verification tests with PyATS step tracking.

        Creates an event loop, builds the FMC client, runs async verification,
        processes results, and ensures cleanup.

        Args:
            steps: PyATS steps object for test reporting and step management.
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            self.client = self.get_fmc_client()
            results = loop.run_until_complete(self.run_verification_async())
            self.process_results_smart(results, steps)
        finally:
            if self.client is not None:
                loop.run_until_complete(self.client.aclose())
            loop.close()
