"""ACI adapter module for PyATS common utilities.

This module provides the core ACI-specific components for PyATS testing, including
authentication handling and base test classes. It serves as the primary interface
for interacting with Cisco ACI (Application Centric Infrastructure) environments
within the PyATS testing framework.

The module exports two primary components:
1. APICAuth: Handles authentication and session management for APIC controllers
2. APICTestBase: Provides the base class for all ACI-specific PyATS tests

Example:
    Basic usage of the ACI module components:

    ```python
    from nac_test_pyats_common.aci import APICAuth, APICTestBase

    # Create authentication handler
    auth = APICAuth(
        controller_url="https://apic.example.com",
        username="admin",
        password="password123"
    )

    # Use in a test class
    class MyACITest(APICTestBase):
        def setup(self):
            self.auth = auth
            super().setup()
    ```

Note:
    This module is specifically designed for testing ACI environments and requires
    proper APIC controller access and credentials for full functionality.
"""

from .auth import APICAuth
from .test_base import APICTestBase

__all__ = ["APICAuth", "APICTestBase"]
