# nac-test-pyats-common: Product Requirements & Architecture Documentation

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Quick Start Guide for Test Authors](#quick-start-guide-for-test-authors)
   - [Writing an API Test](#writing-an-api-test)
   - [Writing an SSH/D2D Test](#writing-an-sshd2d-test)
   - [Using IOSXETestBase (Architecture-Agnostic)](#using-iosxetestbase-architecture-agnostic)
   - [Choosing the Right Test Base](#choosing-the-right-test-base)
   - [Test Author API Quick Reference](#test-author-api-quick-reference)
   - [TEST_CONFIG Dictionary Reference](#test_config-dictionary-reference)
   - [Module-Level Constants for HTML Reports](#module-level-constants-for-html-reports)
3. [Package Position in Three-Tier Architecture](#package-position-in-three-tier-architecture)
   - [Architecture Overview](#architecture-overview)
   - [Dependency Flow](#dependency-flow)
   - [Package Responsibilities](#package-responsibilities)
4. [Contract with nac-test Core Framework](#contract-with-nac-test-core-framework)
   - [Imports from nac-test](#imports-from-nac-test)
   - [Interface Contract: NACTestBase](#interface-contract-nactestbase)
   - [Interface Contract: SSHTestBase](#interface-contract-sshtestbase)
   - [Interface Contract: AuthCache](#interface-contract-authcache)
5. [Test Execution Flow](#test-execution-flow)
   - [API Test Lifecycle](#api-test-lifecycle)
   - [SSH/D2D Test Lifecycle](#sshd2d-test-lifecycle)
6. [Module Structure](#module-structure)
   - [Directory Layout](#directory-layout)
   - [Public API Exports](#public-api-exports)
7. [Architecture Adapters](#architecture-adapters)
   - [ACI (APIC) Adapter](#aci-apic-adapter)
   - [SD-WAN Adapter](#sd-wan-adapter)
   - [Catalyst Center Adapter](#catalyst-center-adapter)
   - [IOS-XE Generic Adapter](#ios-xe-generic-adapter)
8. [Authentication System](#authentication-system)
   - [Two-Tier Auth Pattern](#two-tier-auth-pattern)
   - [APICAuth Implementation](#apicauth-implementation)
   - [SDWANManagerAuth Implementation](#sdwanmanagerauth-implementation)
   - [CatalystCenterAuth Implementation](#catalystcenterauth-implementation)
9. [Test Base Classes](#test-base-classes)
   - [API Test Base Classes](#api-test-base-classes)
   - [SSH/D2D Test Base Classes](#sshd2d-test-base-classes)
10. [Device Resolution System](#device-resolution-system)
    - [BaseDeviceResolver: Template Method Pattern](#basedeviceresolver-template-method-pattern)
    - [SDWANDeviceResolver](#sdwandeviceresolver)
    - [CatalystCenterDeviceResolver](#catalystcenterdeviceresolver)
    - [StandaloneIOSXEResolver](#standaloneiosxeresolver)
11. [IOS-XE Generic TestBase with Auto-Detection](#ios-xe-generic-testbase-with-auto-detection)
    - [IOSXETestBase Architecture](#iosxetestbase-architecture)
    - [Registry Pattern](#registry-pattern)
    - [Architecture Detection Flow](#architecture-detection-flow)
12. [Environment Variables](#environment-variables)
    - [Controller Credentials](#controller-credentials)
    - [Device Credentials](#device-credentials)
13. [Error Handling](#error-handling)
14. [Test Inventory System](#test-inventory-system)
    - [Test Inventory File Format](#test-inventory-file-format)
    - [Architecture-Specific Test Inventory](#architecture-specific-test-inventory)
    - [How Device Matching Works](#how-device-matching-works)
15. [Standalone Deployment Guide](#standalone-deployment-guide)
    - [When to Use Standalone Mode](#when-to-use-standalone-mode)
    - [Complete Standalone Setup](#complete-standalone-setup)
    - [Standalone Detection Logic](#standalone-detection-logic)
16. [Complete Test Examples](#complete-test-examples)
    - [Example: SD-WAN Manager API Test](#example-sd-wan-manager-api-test)
    - [Example: IOS-XE SSH Test (Architecture-Agnostic)](#example-ios-xe-ssh-test-architecture-agnostic)
17. [Schema Navigation Reference](#schema-navigation-reference)
18. [Contributor Guide](#contributor-guide)
    - [Adding New Architecture Adapters](#adding-new-architecture-adapters)
    - [Adding IOS-XE Resolvers](#adding-ios-xe-resolvers)
19. [Troubleshooting Guide](#troubleshooting-guide)
    - [Common Issues and Solutions](#common-issues-and-solutions)
    - [Debug Logging](#debug-logging)

---

## Executive Summary

**nac-test-pyats-common** is the architecture adapter layer in the NAC testing infrastructure. It provides architecture-specific authentication, test base classes, and device resolver implementations that sit between the core nac-test framework and the architecture-specific test repositories.

**Key Capabilities:**

- Architecture-specific authentication with token caching (APIC, SDWAN Manager, Catalyst Center)
- Test base classes for API testing with automatic response tracking
- Test base classes for SSH/D2D testing with device inventory resolution
- Template Method pattern for device resolution across different NAC schemas
- Generic IOS-XE TestBase with automatic architecture detection
- Plugin architecture for registering new controller-specific resolvers

**Version:** 1.0.0
**Python Requirement:** 3.10+
**Primary Dependencies:** nac-test, httpx, pyyaml

---

## Quick Start Guide for Test Authors

This section provides practical examples for test authors who want to write tests using this package. All tests are written in the architecture repositories (nac-aci-terraform, nac-sdwan-terraform, etc.), NOT in this package.

### Writing an API Test

API tests query controller REST APIs (APIC, SDWAN Manager, Catalyst Center) to verify configuration state.

**Minimal API Test Structure:**

```python
"""verify_something.py - in your architecture repository (e.g., nac-aci-terraform/tests/)"""

from pyats import aetest
from nac_test_pyats_common.aci import APICTestBase  # or SDWANManagerTestBase, CatalystCenterTestBase
from nac_test.pyats_core.reporting.types import ResultStatus

TITLE = "Verify Something"
DESCRIPTION = "Test description for HTML report."

class Test(APICTestBase):
    """Your test class must extend the appropriate TestBase."""

    TEST_CONFIG = {
        "resource_type": "Tenant",           # For HTML report grouping
        "api_endpoint": "/api/class/fvTenant.json",
    }

    @aetest.test
    def test_something(self, steps):
        """Entry point - delegates to base class orchestration."""
        self.run_async_verification_test(steps)

    def get_items_to_verify(self):
        """Return list of items to verify (from data model or discovered)."""
        # Load from data model:
        return self.data.get("apic", {}).get("tenants", [])

    async def verify_item(self, semaphore, client, context):
        """Verify a single item. Called once per item from get_items_to_verify()."""
        async with semaphore:
            response = await client.get(self.TEST_CONFIG["api_endpoint"])
            # ... validation logic ...
            return self.format_verification_result(
                status=ResultStatus.PASSED,
                context=context,
                reason="Verification passed",
                api_duration=0.5,
            )
```

### Writing an SSH/D2D Test

SSH tests connect directly to network devices to execute commands and verify operational state.

**Minimal SSH Test Structure:**

```python
"""verify_ospf.py - in your architecture repository (e.g., nac-sdwan-terraform/tests/d2d/)"""

from pyats import aetest
from nac_test_pyats_common.sdwan import SDWANTestBase  # Architecture-specific
# OR for architecture-agnostic:
from nac_test_pyats_common.iosxe import IOSXETestBase
from nac_test.pyats_core.reporting.types import ResultStatus

TITLE = "Verify OSPF Neighbors"
DESCRIPTION = "Verify all OSPF neighbors are in FULL state."

class Test(IOSXETestBase):  # or SDWANTestBase for SD-WAN specific
    """SSH test extends SSHTestBase (via IOSXETestBase or SDWANTestBase)."""

    TEST_CONFIG = {
        "resource_type": "OSPF Neighbor",
        "api_endpoint": "show ip ospf neighbor",  # CLI command, not REST endpoint
    }

    @aetest.test
    def test_ospf(self, steps):
        """Entry point - delegates to base class orchestration."""
        self.run_async_verification_test(steps)

    def get_items_to_verify(self):
        """Return list of contexts to verify (usually just one for NRFU tests)."""
        return [{"check_type": "ospf_neighbors"}]

    async def verify_item(self, semaphore, client, context):
        """Execute CLI command and verify output."""
        async with semaphore:
            output = await self.execute_command("show ip ospf neighbor detail")
            parsed = self.parse_output("show ip ospf neighbor detail", output=output)
            # ... validation logic ...
            return self.format_verification_result(
                status=ResultStatus.PASSED,
                context=context,
                reason="All OSPF neighbors in FULL state",
                api_duration=0.5,
            )
```

### Using IOSXETestBase (Architecture-Agnostic)

`IOSXETestBase` automatically detects the architecture (SD-WAN, Catalyst Center, Standalone) and uses the appropriate device resolver. This enables writing tests that work across multiple deployment types.

**Benefits:**
- Write one test that works on SD-WAN, Catalyst Center, and standalone deployments
- Automatic architecture detection via environment variables or data model structure
- No code changes needed when switching between deployments

**How it works:**
1. Set environment variables for your controller (SDWAN_URL, CC_URL, etc.)
2. IOSXETestBase detects the controller type automatically
3. The appropriate resolver extracts devices from your NAC data model
4. Your test runs against those devices via SSH

**Example:**
```python
from nac_test_pyats_common.iosxe import IOSXETestBase

class Test(IOSXETestBase):
    # This test works on SD-WAN, Catalyst Center, AND standalone deployments
    # without any code changes - just different environment variables
    ...
```

**Environment variable detection priority:**
1. `SDWAN_URL` + `SDWAN_USERNAME` + `SDWAN_PASSWORD` → SD-WAN architecture
2. `CC_URL` + `CC_USERNAME` + `CC_PASSWORD` → Catalyst Center architecture
3. Neither set → Infer from data model structure (sdwan key, catalyst_center key, or devices key)

### Choosing the Right Test Base

Use this decision table to select the appropriate base class:

| Architecture | Test Type | Base Class | Credentials Needed |
|-------------|-----------|------------|-------------------|
| ACI/APIC | API | `APICTestBase` | APIC_URL, APIC_USERNAME, APIC_PASSWORD |
| SD-WAN | API | `SDWANManagerTestBase` | SDWAN_URL, SDWAN_USERNAME, SDWAN_PASSWORD |
| SD-WAN | SSH/D2D | `SDWANTestBase` | SDWAN_* (for detection) + IOSXE_USERNAME, IOSXE_PASSWORD |
| SD-WAN | SSH/D2D | `IOSXETestBase` | Same as SDWANTestBase (auto-detects) |
| Catalyst Center | API | `CatalystCenterTestBase` | CC_URL, CC_USERNAME, CC_PASSWORD |
| Catalyst Center | SSH/D2D | `IOSXETestBase` | CC_* (for detection) + IOSXE_USERNAME, IOSXE_PASSWORD |
| Standalone | SSH/D2D | `IOSXETestBase` | IOSXE_USERNAME, IOSXE_PASSWORD |
| Multi-arch | SSH/D2D | `IOSXETestBase` | Depends on deployment (auto-detects) |

**When to use `IOSXETestBase` vs `SDWANTestBase`:**
- Use `IOSXETestBase` for **portable tests** that should work across SD-WAN, Catalyst Center, and standalone
- Use `SDWANTestBase` for **SD-WAN-only tests** that use SD-WAN-specific features

### Test Author API Quick Reference

These methods are inherited from nac-test's base classes and available in all test bases:

#### Methods You MUST Implement

| Method | Signature | Purpose |
|--------|-----------|---------|
| `get_items_to_verify()` | `() -> list[dict]` | Return items to verify from data model |
| `verify_item()` | `(semaphore, client, context) -> dict` | Verify a single item, return result |

#### Methods You CALL (Inherited from nac-test)

| Method | Purpose |
|--------|---------|
| `self.run_async_verification_test(steps)` | Entry point - call from `@aetest.test` method |
| `self.format_verification_result(status, context, reason, api_duration)` | Create standardized result dict |
| `self.build_api_context(resource_type, identifier, **kwargs)` | Build context for API call tracking |
| `self.wrap_client_for_tracking(client, device_name)` | Wrap HTTP client for HTML report tracking |

#### Attributes Available in Tests

| Attribute | Type | Description |
|-----------|------|-------------|
| `self.data` | `dict` | Merged data model (all YAML files) |
| `self.controller_url` | `str` | Controller base URL |
| `self.client` | `httpx.AsyncClient` | Pre-configured HTTP client |
| `self.logger` | `Logger` | Configured logger instance |
| `self.pool` | `ConnectionPool` | HTTP client pool |

#### SSH-Specific Methods (SSHTestBase)

| Method | Purpose |
|--------|---------|
| `await self.execute_command(command)` | Execute CLI command, return output |
| `self.parse_output(command, output=output)` | Parse output with Genie parser |

#### Result Status Values

```python
from nac_test.pyats_core.reporting.types import ResultStatus

ResultStatus.PASSED    # Test passed
ResultStatus.FAILED    # Test failed
ResultStatus.SKIPPED   # Test skipped (e.g., no data)
ResultStatus.ERRORED   # Test errored (exception)
ResultStatus.INFO      # Informational result
```

#### TEST_CONFIG Dictionary Reference

Every test class should define a `TEST_CONFIG` class variable for configuration:

```python
class Test(APICTestBase):
    TEST_CONFIG = {
        # REQUIRED: Human-readable name for HTML reports
        "resource_type": "Tenant",

        # REQUIRED: API endpoint or CLI command
        "api_endpoint": "/api/class/fvTenant.json",

        # OPTIONAL: Expected values for validation
        "expected_values": {
            "state": "normal",
            "required_status": "active",
        },

        # OPTIONAL: Fields to include in log output
        "log_fields": [
            "check_type",
            "total_items",
            "passed_items",
        ],
    }
```

| Key | Required | Description |
|-----|----------|-------------|
| `resource_type` | Yes | Human-readable name shown in HTML reports (e.g., "Tenant", "OSPF Neighbor") |
| `api_endpoint` | Yes | REST API path (API tests) or CLI command (SSH tests) |
| `expected_values` | No | Dict of expected values for validation logic |
| `log_fields` | No | List of context keys to include in log output |

#### Module-Level Constants for HTML Reports

Each test file should define these module-level constants for rich HTML report generation:

```python
"""verify_tenants.py"""

# REQUIRED: Test title shown in report header
TITLE = "Verify All Tenants Exist"

# REQUIRED: Test description (supports Markdown)
DESCRIPTION = """Validates that all tenants defined in the data model
exist on the APIC controller with correct configuration."""

# OPTIONAL: Setup prerequisites
SETUP = (
    "* Access to APIC controller via HTTPS API.\\n"
    "* Valid APIC credentials configured.\\n"
)

# OPTIONAL: Test procedure steps
PROCEDURE = (
    "* Query APIC for all fvTenant objects.\\n"
    "* Compare against data model definitions.\\n"
    "* Verify each tenant's properties match.\\n"
)

# OPTIONAL: Pass/fail criteria
PASS_FAIL_CRITERIA = (
    "**This test passes when:**\\n"
    "* All tenants from data model exist on APIC.\\n"
    "\\n"
    "**This test fails if:**\\n"
    "* Any tenant is missing or misconfigured.\\n"
)
```

| Constant | Required | Description |
|----------|----------|-------------|
| `TITLE` | Yes | Short title for the test (shown in report header) |
| `DESCRIPTION` | Yes | Longer description (Markdown supported) |
| `SETUP` | No | Prerequisites and setup requirements |
| `PROCEDURE` | No | Step-by-step test procedure |
| `PASS_FAIL_CRITERIA` | No | Explicit pass/fail conditions |

---

## Package Position in Three-Tier Architecture

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│               Layer 3: Architecture Repositories                     │
│     (nac-aci-terraform, nac-sdwan-terraform, nac-catc-terraform)    │
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐                          │
│  │ Test Files      │  │ NAC Schema      │                          │
│  │ (verify_*.py)   │  │ Definitions     │                          │
│  └────────┬────────┘  └─────────────────┘                          │
│           │                                                          │
│           │ imports                                                  │
│           ▼                                                          │
└───────────┼──────────────────────────────────────────────────────────┘
            │
┌───────────▼──────────────────────────────────────────────────────────┐
│    Layer 2: nac-test-pyats-common (Architecture Adapters) ← YOU ARE │
│                       DEPENDS ON nac-test                            │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  nac_test_pyats_common/                                      │   │
│  │  ├── __init__.py          # Version + public exports         │   │
│  │  ├── py.typed             # PEP 561 marker                   │   │
│  │  │                                                           │   │
│  │  ├── common/              # Shared base classes              │   │
│  │  │   └── base_device_resolver.py  # Template Method pattern  │   │
│  │  │                                                           │   │
│  │  ├── aci/                 # ACI/APIC adapter                 │   │
│  │  │   ├── auth.py          # APICAuth implementation          │   │
│  │  │   └── test_base.py     # APICTestBase                     │   │
│  │  │                                                           │   │
│  │  ├── sdwan/               # SD-WAN adapter                   │   │
│  │  │   ├── auth.py          # SDWANManagerAuth                 │   │
│  │  │   ├── api_test_base.py # SDWANManagerTestBase             │   │
│  │  │   ├── ssh_test_base.py # SDWANTestBase                    │   │
│  │  │   └── device_resolver.py # SDWANDeviceResolver            │   │
│  │  │                                                           │   │
│  │  ├── catc/                # Catalyst Center adapter          │   │
│  │  │   ├── auth.py          # CatalystCenterAuth               │   │
│  │  │   └── test_base.py     # CatalystCenterTestBase           │   │
│  │  │                                                           │   │
│  │  └── iosxe/               # Generic IOS-XE adapter           │   │
│  │      ├── registry.py      # Resolver registry pattern        │   │
│  │      ├── test_base.py     # IOSXETestBase (auto-detect)      │   │
│  │      ├── catc_resolver.py # Catalyst Center resolver         │   │
│  │      └── standalone_resolver.py # Standalone resolver        │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                       │                                              │
│                       │ imports NACTestBase, SSHTestBase, AuthCache │
│                       ▼                                              │
└───────────────────────┼──────────────────────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────────────────────┐
│                Layer 1: nac-test (Core Framework)                    │
│                    Orchestration + Generic Infrastructure            │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  • NACTestBase, SSHTestBase (generic base classes)          │   │
│  │  • AuthCache (file-based token caching)                     │   │
│  │  • ConnectionPool (HTTP client management)                  │   │
│  │  • Test orchestration and reporting                         │   │
│  │  • detect_controller_type() utility                         │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Dependency Flow

```
Architecture Repos (Layer 3)
        │
        │ pip install nac-test-pyats-common
        ▼
┌───────────────────────────────────────────────────────────────┐
│              nac-test-pyats-common (Layer 2)                  │
│   • Auth classes (APICAuth, SDWANManagerAuth, etc.)          │
│   • Test base classes (APICTestBase, SDWANTestBase, etc.)    │
│   • Device resolvers (SDWANDeviceResolver, etc.)             │
│   • IOSXETestBase with auto-detection                        │
└───────────────────────────────────────────────────────────────┘
        │
        │ pip install nac-test (dependency)
        ▼
┌───────────────────────────────────────────────────────────────┐
│                      nac-test (Layer 1)                       │
│   • Generic base classes                                      │
│   • Auth caching infrastructure                               │
│   • Test orchestration                                        │
│   • Controller type detection                                 │
└───────────────────────────────────────────────────────────────┘
```

**Key Points:**
1. **Architecture repos only need `pip install nac-test-pyats-common`** - it brings `nac-test` as a transitive dependency
2. **No circular dependencies** - clean unidirectional flow
3. **Architecture-specific code stays here** - auth, test bases, resolvers

### Package Responsibilities

| Responsibility | nac-test | nac-test-pyats-common |
|---------------|----------|----------------------|
| Test orchestration | ✓ | |
| Generic base classes | ✓ | |
| Auth token caching | ✓ | |
| Architecture-specific auth | | ✓ |
| Architecture-specific test bases | | ✓ |
| Device resolvers | | ✓ |
| NAC schema navigation | | ✓ |
| Test files | | | (Layer 3 repos)

---

## Contract with nac-test Core Framework

This section documents the interface contract between nac-test-pyats-common and the nac-test core framework. Understanding this contract is critical for both using and extending the adapters.

### Imports from nac-test

```python
# All imports from nac-test used by this package:

# Base test classes (extended by architecture-specific test bases)
from nac_test.pyats_core.common.base_test import NACTestBase
from nac_test.pyats_core.common.ssh_base_test import SSHTestBase

# Authentication caching infrastructure
from nac_test.pyats_core.common.auth_cache import AuthCache

# Controller type detection utility
from nac_test.utils.controller import detect_controller_type

# File discovery utility (for test_inventory.yaml)
from nac_test.utils.file_discovery import find_data_file

# Result status enum for verification results
from nac_test.pyats_core.reporting.types import ResultStatus
```

### Interface Contract: NACTestBase

`NACTestBase` is the parent class for all API test bases. Architecture-specific test bases (APICTestBase, SDWANManagerTestBase, CatalystCenterTestBase) extend this class.

**Inherited Attributes:**
```python
class NACTestBase:
    data: dict[str, Any]           # Merged data model (loaded automatically)
    controller_url: str            # From env vars (APIC_URL, SDWAN_URL, CC_URL)
    username: str                  # From env vars
    password: str                  # From env vars
    pool: ConnectionPool           # HTTP client pool for connection reuse
    logger: logging.Logger         # Configured logger
```

**Inherited Methods (must be called or extended):**
```python
class NACTestBase:
    def setup(self) -> None:
        """Called by PyATS before tests. Sets up data, pool, logging."""
        # MUST call super().setup() in subclass setup

    def wrap_client_for_tracking(
        self, client: httpx.AsyncClient, device_name: str
    ) -> httpx.AsyncClient:
        """Wrap HTTP client for automatic API call tracking in HTML reports."""

    async def run_verification_async(self) -> list[dict]:
        """Execute verification loop. Calls get_items_to_verify() and verify_item()."""

    def process_results_smart(self, results: list[dict], steps: Any) -> None:
        """Process verification results and create PyATS steps."""

    def format_verification_result(
        self, status: ResultStatus, context: dict, reason: str, api_duration: float
    ) -> dict:
        """Create standardized verification result dictionary."""

    def build_api_context(
        self, resource_type: str, identifier: str, **kwargs
    ) -> dict:
        """Build context dictionary for API call tracking."""
```

**Methods subclasses MUST implement:**
```python
class YourTestBase(NACTestBase):
    def get_items_to_verify(self) -> list[dict]:
        """Return list of items to verify from data model or discovery."""
        raise NotImplementedError

    async def verify_item(
        self, semaphore: asyncio.Semaphore, client: httpx.AsyncClient, context: dict
    ) -> dict:
        """Verify a single item. Return result via format_verification_result()."""
        raise NotImplementedError
```

### Interface Contract: SSHTestBase

`SSHTestBase` is the parent class for SSH/D2D test bases. Architecture-specific SSH bases (SDWANTestBase, IOSXETestBase) extend this class.

**Key Difference from NACTestBase:**
- Requires `get_ssh_device_inventory()` classmethod instead of using data model directly
- Provides `execute_command()` and `parse_output()` for CLI operations
- Device iteration is handled by the orchestrator, not the test

**Inherited Attributes (same as NACTestBase, plus):**
```python
class SSHTestBase(NACTestBase):
    device: dict[str, Any]         # Current device being tested (set by orchestrator)
```

**Methods subclasses MUST implement:**
```python
class YourSSHTestBase(SSHTestBase):
    @classmethod
    def get_ssh_device_inventory(cls, data_model: dict[str, Any]) -> list[dict[str, Any]]:
        """Return list of device dicts with connection info.

        Each device dict must contain:
        - hostname: str
        - host: str (IP address)
        - os: str (e.g., "iosxe")
        - username: str
        - password: str
        - device_id: str (optional, for identification)
        """
        raise NotImplementedError

    def get_device_credentials(self, device: dict[str, Any]) -> dict[str, str | None]:
        """Return credentials dict with 'username' and 'password' keys."""
        raise NotImplementedError
```

**Inherited Methods for SSH operations:**
```python
class SSHTestBase:
    async def execute_command(self, command: str) -> str:
        """Execute CLI command on current device and return output."""

    def parse_output(self, command: str, output: str) -> dict | None:
        """Parse command output using Genie parser."""
```

### Interface Contract: AuthCache

`AuthCache` provides file-based token caching with process-safe locking. All auth classes use this for efficient token reuse.

**Usage Pattern:**
```python
class YourAuth:
    @classmethod
    def get_auth(cls) -> dict[str, Any]:
        def auth_wrapper() -> tuple[dict[str, Any], int]:
            # Perform actual authentication
            return {"token": "..."}, 3600  # auth_data, expires_in_seconds

        return AuthCache.get_or_create(
            controller_type="YOUR_TYPE",  # Cache key prefix
            url=url,                       # Cache key suffix
            auth_func=auth_wrapper,        # Called only if cache miss
        )
```

**Cache Behavior:**
- Tokens cached in `~/.nac_test/auth_cache/` directory
- File-based locking prevents parallel auth requests
- TTL-based expiration (honors `expires_in` from auth response)
- Automatic cleanup of expired tokens

---

## Test Execution Flow

### API Test Lifecycle

```
┌─────────────────────────────────────────────────────────────────────┐
│                     API Test Execution Flow                          │
│                                                                      │
│  1. Test Discovery (nac-test)                                       │
│     └─ PyATS discovers verify_*.py files in tests/ directory        │
│                                                                      │
│  2. Test Setup                                                       │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  @aetest.setup                                           │    │
│     │  def setup(self):                                        │    │
│     │      super().setup()           # NACTestBase.setup()     │    │
│     │      │                         # - Loads data model      │    │
│     │      │                         # - Sets controller_url   │    │
│     │      │                         # - Initializes pool      │    │
│     │      │                                                   │    │
│     │      self.auth = XAuth.get_auth()  # Get cached auth    │    │
│     │      │                         # - Checks AuthCache      │    │
│     │      │                         # - If miss: _authenticate()│   │
│     │      │                         # - Returns token/session │    │
│     │      │                                                   │    │
│     │      self.client = self.get_client()  # Create HTTP client│   │
│     │                                # - pool.get_client()    │    │
│     │                                # - wrap_client_for_tracking()│ │
│     └─────────────────────────────────────────────────────────┘    │
│                                                                      │
│  3. Test Execution                                                   │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  @aetest.test                                            │    │
│     │  def test_something(self, steps):                        │    │
│     │      self.run_async_verification_test(steps)             │    │
│     │      │                                                   │    │
│     │      └─→ Creates event loop                              │    │
│     │          └─→ run_verification_async()                    │    │
│     │              │                                           │    │
│     │              ├─→ get_items_to_verify()                   │    │
│     │              │   └─ Returns list of items from data model│    │
│     │              │                                           │    │
│     │              └─→ For each item (concurrent):             │    │
│     │                  └─→ verify_item(semaphore, client, ctx) │    │
│     │                      ├─ Make API call(s)                 │    │
│     │                      ├─ Validate response                │    │
│     │                      └─ Return format_verification_result()│  │
│     │                                                          │    │
│     │          └─→ process_results_smart(results, steps)       │    │
│     │              └─ Creates PyATS steps for each result      │    │
│     └─────────────────────────────────────────────────────────┘    │
│                                                                      │
│  4. Cleanup                                                          │
│     └─ Event loop closed, HTTP client closed                        │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### SSH/D2D Test Lifecycle

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SSH/D2D Test Execution Flow                       │
│                                                                      │
│  1. Test Discovery (nac-test)                                       │
│     └─ PyATS discovers verify_*.py files in tests/d2d/ directory    │
│     └─ D2D orchestrator identifies SSH test bases                   │
│                                                                      │
│  2. Device Inventory Resolution (BEFORE test instantiation)         │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  # Orchestrator calls classmethod:                       │    │
│     │  devices = TestClass.get_ssh_device_inventory(data_model)│    │
│     │                                                          │    │
│     │  # For IOSXETestBase, this triggers auto-detection:      │    │
│     │  ┌───────────────────────────────────────────────────┐  │    │
│     │  │ 1. detect_controller_type()                       │  │    │
│     │  │    └─ Checks SDWAN_URL, CC_URL env vars           │  │    │
│     │  │                                                   │  │    │
│     │  │ 2. If UNKNOWN, infer from data model:             │  │    │
│     │  │    └─ "sdwan" key → SDWAN                         │  │    │
│     │  │    └─ "catalyst_center" key → CC                  │  │    │
│     │  │    └─ "devices" key → IOSXE                  │  │    │
│     │  │                                                   │  │    │
│     │  │ 3. Get resolver from registry:                    │  │    │
│     │  │    resolver = get_resolver_for_controller(type)   │  │    │
│     │  │                                                   │  │    │
│     │  │ 4. Resolve devices:                               │  │    │
│     │  │    return resolver(data_model).get_resolved_inventory()│  │
│     │  └───────────────────────────────────────────────────┘  │    │
│     │                                                          │    │
│     │  # Returns list of device dicts:                         │    │
│     │  [{"hostname": "router1", "host": "10.1.1.1", ...}, ...] │    │
│     └─────────────────────────────────────────────────────────┘    │
│                                                                      │
│  3. Per-Device Test Execution (parallel across devices)             │
│     ┌─────────────────────────────────────────────────────────┐    │
│     │  For each device in inventory (parallel workers):        │    │
│     │                                                          │    │
│     │  a. SSH Connection (handled by PyATS/Genie)              │    │
│     │     └─ Connect to device.host with device credentials    │    │
│     │                                                          │    │
│     │  b. Test Setup                                           │    │
│     │     @aetest.setup                                        │    │
│     │     def setup(self): ...                                 │    │
│     │                                                          │    │
│     │  c. Test Execution                                       │    │
│     │     @aetest.test                                         │    │
│     │     def test_something(self, steps):                     │    │
│     │         self.run_async_verification_test(steps)          │    │
│     │         │                                                │    │
│     │         └─→ get_items_to_verify()                        │    │
│     │         └─→ verify_item():                               │    │
│     │             ├─ execute_command("show ...")               │    │
│     │             ├─ parse_output() (Genie parser)             │    │
│     │             ├─ Validate parsed data                      │    │
│     │             └─ Return format_verification_result()       │    │
│     │                                                          │    │
│     │  d. SSH Disconnect                                       │    │
│     └─────────────────────────────────────────────────────────┘    │
│                                                                      │
│  4. Results Aggregation                                             │
│     └─ All device results combined into single HTML report          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Module Structure

### Directory Layout

```
nac_test_pyats_common/
├── __init__.py              # Package metadata and public exports
├── py.typed                 # PEP 561 type hint marker
│
├── common/                  # Shared infrastructure
│   ├── __init__.py          # Exports BaseDeviceResolver
│   └── base_device_resolver.py  # Template Method pattern for resolvers
│
├── aci/                     # ACI/APIC adapter
│   ├── __init__.py          # Exports APICAuth, APICTestBase
│   ├── auth.py              # APIC cookie-based authentication
│   └── test_base.py         # APICTestBase for API tests
│
├── sdwan/                   # SD-WAN adapter
│   ├── __init__.py          # Exports all SD-WAN classes
│   ├── auth.py              # SDWAN Manager session auth + XSRF
│   ├── api_test_base.py     # SDWANManagerTestBase for API tests
│   ├── ssh_test_base.py     # SDWANTestBase for D2D tests
│   └── device_resolver.py   # SDWANDeviceResolver for device inventory
│
├── catc/                    # Catalyst Center adapter
│   ├── __init__.py          # Exports CatalystCenterAuth, CatalystCenterTestBase
│   ├── auth.py              # Catalyst Center token auth (Basic Auth)
│   └── test_base.py         # CatalystCenterTestBase for API tests
│
└── iosxe/                   # Generic IOS-XE adapter
    ├── __init__.py          # Exports IOSXETestBase, registry functions
    ├── registry.py          # Plugin architecture for resolvers
    ├── test_base.py         # IOSXETestBase with auto-detection
    ├── catc_resolver.py     # Catalyst Center device resolver
    └── standalone_resolver.py # Standalone device resolver
```

### Public API Exports

```python
# Main package exports (from __init__.py)
from nac_test_pyats_common import (
    # ACI/APIC
    APICAuth,
    APICTestBase,
    # SD-WAN
    SDWANManagerAuth,
    SDWANManagerTestBase,
    SDWANTestBase,
    SDWANDeviceResolver,
    # Catalyst Center
    CatalystCenterAuth,
    CatalystCenterTestBase,
)

# IOS-XE generic (from iosxe subpackage)
from nac_test_pyats_common.iosxe import (
    IOSXETestBase,
    register_iosxe_resolver,
    get_resolver_for_controller,
    get_supported_controllers,
)

# Base classes (from common subpackage)
from nac_test_pyats_common.common import BaseDeviceResolver
```

---

## Architecture Adapters

### ACI (APIC) Adapter

**Purpose:** Test Cisco ACI fabrics via APIC REST API

**Components:**
- `APICAuth`: Cookie-based authentication (`APIC-cookie`)
- `APICTestBase`: Base class for APIC API tests

**Environment Variables:**
- `APIC_URL`: Base URL of APIC controller
- `APIC_USERNAME`: APIC username
- `APIC_PASSWORD`: APIC password

**Auth Flow:**
```
POST /api/aaaLogin.json
  → Response: {"imdata": [{"aaaLogin": {"attributes": {"token": "..."}}}]}
  → Token used as Cookie: APIC-cookie={token}
```

**Token Lifetime:** 600 seconds (10 minutes)

### SD-WAN Adapter

**Purpose:** Test Cisco SD-WAN deployments via SDWAN Manager API and direct device SSH

**Components:**
- `SDWANManagerAuth`: Form-based login with JSESSIONID + XSRF token
- `SDWANManagerTestBase`: Base class for SDWAN Manager API tests
- `SDWANTestBase`: Base class for SSH/D2D tests to edge devices
- `SDWANDeviceResolver`: Device inventory resolution from SD-WAN schema

**Environment Variables (Controller):**
- `SDWAN_URL`: Base URL of SDWAN Manager
- `SDWAN_USERNAME`: SDWAN Manager username
- `SDWAN_PASSWORD`: SDWAN Manager password

**Environment Variables (D2D Devices):**
- `IOSXE_USERNAME`: SSH username for edge devices
- `IOSXE_PASSWORD`: SSH password for edge devices

**Auth Flow:**
```
POST /j_security_check (form data: j_username, j_password)
  → Response: JSESSIONID cookie
GET /dataservice/client/token (19.2+ only)
  → Response: XSRF token text
  → Headers: Cookie: JSESSIONID={id}, X-XSRF-TOKEN: {token}
```

**Session Lifetime:** 1800 seconds (30 minutes)

### Catalyst Center Adapter

**Purpose:** Test Cisco Catalyst Center (formerly DNA Center) via REST API

**Components:**
- `CatalystCenterAuth`: Basic Auth to obtain token
- `CatalystCenterTestBase`: Base class for Catalyst Center API tests

**Environment Variables:**
- `CC_URL`: Base URL of Catalyst Center
- `CC_USERNAME`: Catalyst Center username
- `CC_PASSWORD`: Catalyst Center password
- `CC_INSECURE`: Optional, disable SSL verification (default: True)

**Auth Flow:**
```
POST /api/system/v1/auth/token (or /dna/system/api/v1/auth/token for legacy)
  → Auth: Basic Auth (username:password)
  → Response: {"Token": "..."}
  → Headers: X-Auth-Token: {token}
```

**Token Lifetime:** 3600 seconds (1 hour)

### IOS-XE Generic Adapter

**Purpose:** Architecture-agnostic testing for IOS-XE devices managed by any controller

**Components:**
- `IOSXETestBase`: Auto-detecting base class for SSH/D2D tests
- `register_iosxe_resolver`: Decorator for registering resolvers
- `CatalystCenterDeviceResolver`: Device resolver for Catalyst Center
- `StandaloneIOSXEResolver`: Device resolver for standalone devices

**Supported Controllers:** SD-WAN, Catalyst Center, Standalone

---

## Authentication System

### Two-Tier Auth Pattern

All auth classes follow a consistent two-tier pattern for separation of concerns:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Two-Tier Auth Pattern                         │
│                                                                  │
│  Tier 1: Low-Level Authentication                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  _authenticate(url, username, password)                  │   │
│  │    → Direct HTTP call to controller                      │   │
│  │    → Returns (auth_data, expires_in)                     │   │
│  │    → Called by AuthCache, not by consumers               │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           │                                      │
│                           │ passed to                            │
│                           ▼                                      │
│  Tier 2: Cached Authentication                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  get_auth() or get_token()                               │   │
│  │    → Primary method for consumers                        │   │
│  │    → Leverages AuthCache from nac-test                   │   │
│  │    → Automatic renewal on expiry                         │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Benefits:**
- Clear separation between HTTP logic and caching
- Single point of cache management (AuthCache in nac-test)
- Efficient token reuse across parallel test execution
- Process-safe file-based locking in AuthCache

### Fork-Safe Subprocess Authentication

All authentication modules use subprocess-based HTTP execution to avoid macOS fork+SSL crashes.

**Problem**: On macOS, after PyATS uses `fork()` to create task subprocesses, SSL/TLS operations crash silently due to OpenSSL threading primitives that are not fork-safe. This affects `httpx`, `aiohttp`, and other HTTP libraries that use SSL.

**Solution**: The `execute_auth_subprocess()` function from nac-test spawns a clean Python subprocess using `os.system()` with temp files:

```
┌─────────────────────────────────────────────────────────────────┐
│               Subprocess Authentication Flow                      │
│                                                                   │
│  1. Write auth_params to temp JSON file                          │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │ /tmp/xxx_auth_input.json                                │ │
│     │ {"url": "...", "username": "...", "password": "..."}    │ │
│     └─────────────────────────────────────────────────────────┘ │
│                           │                                       │
│                           ▼                                       │
│  2. Execute auth script in NEW Python interpreter (os.system)   │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │ python3 /tmp/xxx_auth_script.py                         │ │
│     │   - Reads params from input file                        │ │
│     │   - Performs HTTP auth using urllib (no httpx)          │ │
│     │   - Writes result to output file                        │ │
│     └─────────────────────────────────────────────────────────┘ │
│                           │                                       │
│                           ▼                                       │
│  3. Read result from temp JSON file                              │
│     ┌─────────────────────────────────────────────────────────┐ │
│     │ /tmp/xxx_auth_output.json                               │ │
│     │ {"token": "...", "jsessionid": "..."}                   │ │
│     └─────────────────────────────────────────────────────────┘ │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

**Why os.system() instead of subprocess.run()?**
- `subprocess.run()` creates pipes using `os.pipe()`, which also crashes after fork on macOS
- `os.system()` is the ONLY fork-safe method - it uses `exec()` without pipe creation

**Platform Behavior**:
| Platform | SSL Issue? | Auth Method |
|----------|------------|-------------|
| macOS    | Yes (fork+SSL crash) | Subprocess via os.system() |
| Linux    | No | Subprocess (consistent behavior) |
| Windows  | No (uses spawn, not fork) | Subprocess (consistent behavior) |

**Error Handling**:
- `SubprocessAuthError`: Raised when authentication subprocess fails
- Re-exported from each auth module for convenient import by callers

### APICAuth Implementation

```python
class APICAuth:
    @staticmethod
    def authenticate(url: str, username: str, password: str) -> tuple[str, int]:
        """Low-level: Direct APIC authentication."""
        # POST to /api/aaaLogin.json
        # Returns (token, 600)

    @classmethod
    def get_token(cls, url: str, username: str, password: str) -> str:
        """High-level: Cached token retrieval."""
        return AuthCache.get_or_create_token(
            controller_type="ACI",
            url=url,
            username=username,
            password=password,
            auth_func=cls.authenticate,
        )
```

### SDWANManagerAuth Implementation

```python
class SDWANManagerAuth:
    @staticmethod
    def _authenticate(url: str, username: str, password: str) -> tuple[dict, int]:
        """Low-level: Direct SDWAN Manager authentication."""
        # POST to /j_security_check (form-based)
        # GET /dataservice/client/token (for XSRF)
        # Returns ({"jsessionid": ..., "xsrf_token": ...}, 1800)

    @classmethod
    def get_auth(cls) -> dict[str, Any]:
        """High-level: Cached session retrieval (reads env vars)."""
        # Reads SDWAN_URL, SDWAN_USERNAME, SDWAN_PASSWORD from env
        return AuthCache.get_or_create(
            controller_type="SDWAN_MANAGER",
            url=url,
            auth_func=auth_wrapper,
        )
```

### CatalystCenterAuth Implementation

```python
class CatalystCenterAuth:
    @classmethod
    def _authenticate(cls, url: str, username: str, password: str, verify_ssl: bool) -> tuple[dict, int]:
        """Low-level: Direct Catalyst Center authentication."""
        # POST to /api/system/v1/auth/token (Basic Auth)
        # Fallback to /dna/system/api/v1/auth/token for legacy
        # Returns ({"token": ...}, 3600)

    @classmethod
    def get_auth(cls) -> dict[str, Any]:
        """High-level: Cached token retrieval (reads env vars)."""
        # Reads CC_URL, CC_USERNAME, CC_PASSWORD, CC_INSECURE from env
        return AuthCache.get_or_create(
            controller_type="CC",
            url=url,
            auth_func=auth_wrapper,
        )
```

---

## Test Base Classes

### API Test Base Classes

All API test base classes extend `NACTestBase` from nac-test and follow this pattern:

```
┌─────────────────────────────────────────────────────────────────┐
│                    API Test Base Pattern                         │
│                                                                  │
│  class ArchitectureTestBase(NACTestBase):                       │
│                                                                  │
│    @aetest.setup                                                │
│    def setup(self):                                             │
│      super().setup()                     # Generic setup         │
│      self.auth = AuthClass.get_auth()    # Get cached auth      │
│      self.client = self.get_client()     # Create HTTP client   │
│                                                                  │
│    def get_client(self) -> httpx.AsyncClient:                   │
│      headers = {...auth headers...}                             │
│      base_client = self.pool.get_client(...)                    │
│      return self.wrap_client_for_tracking(base_client)          │
│                                                                  │
│    def run_async_verification_test(self, steps):                │
│      loop = asyncio.new_event_loop()                            │
│      results = loop.run_until_complete(self.run_verification_async())│
│      self.process_results_smart(results, steps)                 │
│      # ... cleanup ...                                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Available Classes:**
- `APICTestBase`: For ACI/APIC API tests
- `SDWANManagerTestBase`: For SDWAN Manager API tests
- `CatalystCenterTestBase`: For Catalyst Center API tests

### SSH/D2D Test Base Classes

SSH test base classes extend `SSHTestBase` from nac-test:

```
┌─────────────────────────────────────────────────────────────────┐
│                    SSH Test Base Pattern                         │
│                                                                  │
│  class ArchitectureTestBase(SSHTestBase):                       │
│                                                                  │
│    @classmethod                                                 │
│    def get_ssh_device_inventory(cls, data_model) -> list[dict]: │
│      # Return device inventory for SSH testing                  │
│      # Uses DeviceResolver to navigate NAC schema               │
│      resolver = ArchitectureDeviceResolver(data_model)          │
│      return resolver.get_resolved_inventory()                   │
│                                                                  │
│    def get_device_credentials(self, device) -> dict:            │
│      return {                                                   │
│        "username": os.environ.get("IOSXE_USERNAME"),            │
│        "password": os.environ.get("IOSXE_PASSWORD"),            │
│      }                                                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Available Classes:**
- `SDWANTestBase`: For SD-WAN edge device SSH tests
- `IOSXETestBase`: Generic IOS-XE test base with auto-detection

---

## Device Resolution System

### BaseDeviceResolver: Template Method Pattern

The `BaseDeviceResolver` abstract class implements the Template Method pattern for device inventory resolution. Architecture-specific resolvers extend this class and implement abstract methods for schema navigation.

```
┌─────────────────────────────────────────────────────────────────┐
│              BaseDeviceResolver (Template Method)                │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  get_resolved_inventory()      [Template Method]         │   │
│  │    1. Navigate data model via navigate_to_devices()      │   │
│  │    2. Match against test_inventory                       │   │
│  │    3. Extract fields via extract_* methods               │   │
│  │    4. Inject credentials via get_credential_env_vars()   │   │
│  │    5. Return list of device dicts                        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           │                                      │
│            Calls abstract methods (must implement)               │
│                           │                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Abstract Methods:                                       │   │
│  │    • get_architecture_name() → str                       │   │
│  │    • get_schema_root_key() → str                         │   │
│  │    • navigate_to_devices() → list[dict]                  │   │
│  │    • extract_device_id(device_data) → str                │   │
│  │    • extract_hostname(device_data) → str                 │   │
│  │    • extract_host_ip(device_data) → str                  │   │
│  │    • extract_os_type(device_data) → str                  │   │
│  │    • get_credential_env_vars() → tuple[str, str]         │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### SDWANDeviceResolver

Navigates SD-WAN NAC schema: `sdwan.sites[].routers[]`

```yaml
# SD-WAN Schema Structure
sdwan:
  sites:
    - name: "site1"
      routers:
        - chassis_id: "abc123"           # → device_id
          device_variables:
            system_hostname: "router1"   # → hostname
            vpn10_mgmt_ip: "10.1.1.100/32"  # → host (strips /32)
          management_ip_variable: "vpn10_mgmt_ip"
```

**Field Mapping:**
| Abstract Method | SD-WAN Implementation |
|-----------------|----------------------|
| `get_architecture_name()` | `"sdwan"` |
| `get_schema_root_key()` | `"sdwan"` |
| `extract_device_id()` | `device_data["chassis_id"]` |
| `extract_hostname()` | `device_data["device_variables"]["system_hostname"]` |
| `extract_host_ip()` | Variable from `management_ip_variable`, strip CIDR |
| `extract_os_type()` | `device_data.get("os", "iosxe")` |
| `get_credential_env_vars()` | `("IOSXE_USERNAME", "IOSXE_PASSWORD")` |

### CatalystCenterDeviceResolver

Navigates Catalyst Center NAC schema: `catalyst_center.inventory.devices[]`

```yaml
# Catalyst Center Schema Structure
catalyst_center:
  inventory:
    devices:
      - name: "BR10"                  # → device_id
        fqdn_name: "BR10.cisco.eu"   # → hostname (preferred)
        device_ip: "198.18.130.10"   # → host
        pid: "C9KV-UADP-8P"
        state: "INIT"
        device_role: "BORDER ROUTER"
        site: "Global/Poland/Krakow/Bld A"
```

**Field Mapping:**
| Abstract Method | Catalyst Center Implementation |
|-----------------|-------------------------------|
| `get_architecture_name()` | `"catalyst_center"` |
| `get_schema_root_key()` | `"catalyst_center"` |
| `extract_device_id()` | `device_data["name"]` |
| `extract_hostname()` | `device_data["fqdn_name"]` or `device_data["name"]` |
| `extract_host_ip()` | `device_data["device_ip"]` |
| `extract_os_type()` | `device_data.get("os", "iosxe")` |
| `get_credential_env_vars()` | `("IOSXE_USERNAME", "IOSXE_PASSWORD")` |

### StandaloneIOSXEResolver

For devices managed without a controller: `devices[]`

```yaml
# Standalone Schema Structure
devices:
  - hostname: "router1"         # → hostname, device_id
    host: "10.1.1.100"          # → host
    os: "iosxe"                 # → os_type
```

**Field Mapping:**
| Abstract Method | Standalone Implementation |
|-----------------|--------------------------|
| `get_architecture_name()` | `"iosxe"` |
| `get_schema_root_key()` | `"devices"` |
| `extract_device_id()` | `device_data["device_id"]` or `device_data["hostname"]` |
| `extract_hostname()` | `device_data["hostname"]` |
| `extract_host_ip()` | `device_data["host"]` or `device_data["management_ip"]` |
| `extract_os_type()` | `device_data.get("os", "iosxe")` |
| `get_credential_env_vars()` | `("IOSXE_USERNAME", "IOSXE_PASSWORD")` |

---

## IOS-XE Generic TestBase with Auto-Detection

### IOSXETestBase Architecture

`IOSXETestBase` enables architecture-agnostic IOS-XE device tests. Test authors write one test that works across SD-WAN, Catalyst Center, and standalone deployments.

```
┌─────────────────────────────────────────────────────────────────┐
│                   IOSXETestBase Flow                             │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  get_ssh_device_inventory(data_model)                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           │                                      │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  1. detect_controller_type()  (from nac-test)            │   │
│  │     ├─ SDWAN_URL set? → "SDWAN"                         │   │
│  │     ├─ CC_URL set? → "CC"                               │   │
│  │     ├─ APIC_URL set? → "ACI" (rejected - not IOS-XE)    │   │
│  │     └─ None set? → "UNKNOWN"                            │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           │                                      │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  2. If UNKNOWN, infer from data model:                   │   │
│  │     ├─ "sdwan" key? → "SDWAN"                           │   │
│  │     ├─ "catalyst_center" key? → "CC"                    │   │
│  │     └─ "devices" key? → "IOSXE"                    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           │                                      │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  3. Validate controller supports IOS-XE                  │   │
│  │     Supported: {"SDWAN", "CC", "IOSXE"}            │   │
│  │     Rejected: ACI, MERAKI, etc. (raise ValueError)      │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           │                                      │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  4. Get resolver from registry                           │   │
│  │     resolver_class = get_resolver_for_controller(type)   │   │
│  │     resolver = resolver_class(data_model)                │   │
│  └─────────────────────────────────────────────────────────┘   │
│                           │                                      │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  5. Return resolved inventory                            │   │
│  │     return resolver.get_resolved_inventory()             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Registry Pattern

The resolver registry enables a plugin architecture for adding new controller-specific resolvers without modifying IOSXETestBase.

```python
# Registry module: iosxe/registry.py

_IOSXE_RESOLVER_REGISTRY: dict[str, type[BaseDeviceResolver]] = {}

@register_iosxe_resolver("SDWAN")
class SDWANDeviceResolver(BaseDeviceResolver):
    ...

@register_iosxe_resolver("CC")
class CatalystCenterDeviceResolver(BaseDeviceResolver):
    ...

@register_iosxe_resolver("IOSXE")
class StandaloneIOSXEResolver(BaseDeviceResolver):
    ...
```

**Registry Functions:**
- `register_iosxe_resolver(controller_type)`: Decorator for registration
- `get_resolver_for_controller(controller_type)`: Retrieve resolver class
- `get_supported_controllers()`: List all registered types

### Architecture Detection Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                Architecture Detection Priority                   │
│                                                                  │
│  1. Environment Variables (via detect_controller_type)          │
│     ┌─────────────────────────────────────────────────────┐    │
│     │ SDWAN_URL + SDWAN_USERNAME + SDWAN_PASSWORD → SDWAN │    │
│     │ CC_URL + CC_USERNAME + CC_PASSWORD → CC             │    │
│     │ APIC_URL + APIC_USERNAME + APIC_PASSWORD → ACI      │    │
│     │   (Rejected: ACI doesn't support IOS-XE devices)    │    │
│     └─────────────────────────────────────────────────────┘    │
│                           │                                      │
│                           │ If no env vars set                   │
│                           ▼                                      │
│  2. Data Model Inference                                        │
│     ┌─────────────────────────────────────────────────────┐    │
│     │ "sdwan" key in data_model → SDWAN                   │    │
│     │ "catalyst_center" key in data_model → CC            │    │
│     │ "devices" key in data_model → IOSXE            │    │
│     └─────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Environment Variables

### Controller Credentials

| Architecture | URL Variable | Username Variable | Password Variable | Other |
|-------------|--------------|-------------------|-------------------|-------|
| ACI (APIC) | `APIC_URL` | `APIC_USERNAME` | `APIC_PASSWORD` | |
| SD-WAN | `SDWAN_URL` | `SDWAN_USERNAME` | `SDWAN_PASSWORD` | |
| Catalyst Center | `CC_URL` | `CC_USERNAME` | `CC_PASSWORD` | `CC_INSECURE` |

### Device Credentials

| Device Type | Username Variable | Password Variable |
|-------------|-------------------|-------------------|
| IOS-XE devices | `IOSXE_USERNAME` | `IOSXE_PASSWORD` |
| NX-OS devices | `NXOS_SSH_USERNAME` | `NXOS_SSH_PASSWORD` |

**Important:** D2D tests connect to network devices, NOT controllers. Use `IOSXE_*` credentials for SD-WAN edges and Catalyst Center managed devices (both are IOS-XE).

---

## Error Handling

### Error Scenarios and Messages

| Scenario | Error Source | Message Pattern |
|----------|--------------|-----------------|
| Multiple controllers detected | `detect_controller_type()` | "Multiple controller credentials detected: SDWAN, CC..." |
| Incomplete credentials | `detect_controller_type()` | "Incomplete controller credentials: SDWAN: missing SDWAN_PASSWORD" |
| No architecture detected | `IOSXETestBase` | "Cannot detect architecture. Data model root keys found: [...]" |
| Controller doesn't support IOS-XE | `IOSXETestBase` | "Controller type 'ACI' does not support IOS-XE devices" |
| No resolver registered | `IOSXETestBase` | "No IOS-XE resolver registered for controller type '...'" |
| Data model missing expected key | `IOSXETestBase` | "Data model missing expected root key 'sdwan' for SDWAN architecture" |
| Missing SSH credentials | `BaseDeviceResolver` | "Missing required credential environment variables: IOSXE_USERNAME, IOSXE_PASSWORD" |

---

## Test Inventory System

### Overview

The device resolver system supports an optional `test_inventory.yaml` file that allows test authors to specify which devices to test. Without this file, all devices from the data model are tested.

### Test Inventory File Format

```yaml
# test_inventory.yaml - placed in the data directory
test_inventory:
  devices:
    - chassis_id: "abc123"           # SD-WAN: match by chassis_id
    - name: "BR10"                   # Catalyst Center: match by name
    - hostname: "router1"            # Standalone: match by hostname
      connection_options:            # Optional: custom SSH settings
        port: 2222
        protocol: ssh
```

### Supported ID Fields

The resolver attempts to match devices using these fields in order:

| Field | Used By |
|-------|---------|
| `chassis_id` | SD-WAN |
| `device_id` | All architectures |
| `node_id` | Generic |
| `hostname` | Standalone |
| `name` | Catalyst Center |

### Architecture-Specific Test Inventory

For architectures with nested schemas, the inventory can be placed under the architecture key:

```yaml
# SD-WAN specific inventory
sdwan:
  test_inventory:
    devices:
      - chassis_id: "C8300-12P2XG-FCC5.BA8A.F3A8"
      - chassis_id: "CSR1000V-DE0F.0A8D.1234"
```

### Custom Connection Options

Test inventory entries can include `connection_options` to override default SSH settings:

```yaml
test_inventory:
  devices:
    - hostname: "router1"
      connection_options:
        port: 22
        protocol: ssh
    - hostname: "router2"
      connection_options:
        port: 830          # NETCONF port
        protocol: netconf
```

### How Device Matching Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Device Matching Flow                              │
│                                                                      │
│  1. Load test_inventory.yaml                                        │
│     └─ Search using find_data_file() from nac-test                 │
│                                                                      │
│  2. Navigate data model to get all devices                          │
│     └─ Architecture-specific: navigate_to_devices()                │
│                                                                      │
│  3. Build device index by ID                                        │
│     └─ Maps device_id → device_data for O(1) lookup                │
│                                                                      │
│  4. For each entry in test_inventory.devices:                       │
│     ├─ Extract ID from inventory entry                              │
│     ├─ Look up device in index                                      │
│     └─ Merge inventory entry with device data                       │
│         (inventory values override data model values)               │
│                                                                      │
│  5. Return matched devices with injected credentials                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Use Cases

| Scenario | Configuration |
|----------|--------------|
| Test all devices | No test_inventory.yaml (default) |
| Test specific devices | List device IDs in test_inventory.yaml |
| Use non-standard SSH port | Add `connection_options.port` to device entry |
| Test specific site's devices | List only those chassis_ids |
| Exclude certain devices | Only list devices you want to test |

---

## Schema Navigation Reference

### SD-WAN Schema

```yaml
sdwan:
  sites:
    - name: "site1"
      routers:
        - chassis_id: "abc123"
          device_variables:
            system_hostname: "router1"
            vpn10_mgmt_ip: "10.1.1.100/32"
          management_ip_variable: "vpn10_mgmt_ip"
          os: "iosxe"
```

**Navigation Path:** `sdwan.sites[].routers[]`

### Catalyst Center Schema

```yaml
catalyst_center:
  inventory:
    devices:
      - name: "BR10"
        fqdn_name: "BR10.cisco.eu"
        device_ip: "198.18.130.10"
        pid: "C9KV-UADP-8P"
        state: "INIT"
        device_role: "BORDER ROUTER"
        site: "Global/Poland/Krakow/Bld A"
```

**Navigation Path:** `catalyst_center.inventory.devices[]`

### Standalone Schema

```yaml
devices:
  - hostname: "router1"
    host: "10.1.1.100"
    os: "iosxe"
    device_id: "rtr1"  # optional, defaults to hostname
```

**Navigation Path:** `devices[]`

---

## Standalone Deployment Guide

This section provides a complete guide for testing IOS-XE devices without a controller.

### When to Use Standalone Mode

Use standalone mode when:
- Testing devices not managed by SD-WAN or Catalyst Center
- Lab environments with direct device access
- Testing devices before controller onboarding
- Simple device validation without controller overhead

### Complete Standalone Setup

**1. Create your data model file (`devices.yaml`):**

```yaml
# devices.yaml - Define your device inventory
devices:
  - hostname: "router1"
    host: "10.1.1.100"
    os: "iosxe"
    device_id: "rtr1"

  - hostname: "router2"
    host: "10.1.1.101"
    os: "iosxe"
    device_id: "rtr2"

  - hostname: "switch1"
    host: "10.1.1.200"
    os: "iosxe"
    device_id: "sw1"
```

**2. Set environment variables (NO controller variables needed):**

```bash
# Only device credentials needed for standalone
export IOSXE_USERNAME="admin"
export IOSXE_PASSWORD="your-device-password"

# Note: Do NOT set SDWAN_URL or CC_URL - this triggers standalone detection
```

**3. Write your test using IOSXETestBase:**

```python
"""verify_device_connectivity.py - Standalone IOS-XE test"""

from pyats import aetest
from nac_test_pyats_common.iosxe import IOSXETestBase
from nac_test.pyats_core.reporting.types import ResultStatus

TITLE = "Verify Device Connectivity"
DESCRIPTION = "Verify all standalone devices are reachable and responding."

class Test(IOSXETestBase):
    """Works automatically in standalone mode when no controller env vars are set."""

    TEST_CONFIG = {
        "resource_type": "Device Connectivity",
        "api_endpoint": "show version",
    }

    @aetest.test
    def test_connectivity(self, steps):
        self.run_async_verification_test(steps)

    def get_items_to_verify(self):
        return [{"check_type": "connectivity"}]

    async def verify_item(self, semaphore, client, context):
        async with semaphore:
            output = await self.execute_command("show version")
            if output and "Cisco IOS" in output:
                return self.format_verification_result(
                    status=ResultStatus.PASSED,
                    context=context,
                    reason="Device responding with valid IOS version",
                    api_duration=0.5,
                )
            return self.format_verification_result(
                status=ResultStatus.FAILED,
                context=context,
                reason="Device not responding or unexpected output",
                api_duration=0.5,
            )
```

**4. Run the test:**

```bash
nac-test -d devices.yaml -t templates/ -o output/ --pyats
```

### Standalone Detection Logic

IOSXETestBase automatically detects standalone mode when:

```
┌─────────────────────────────────────────────────────────────────────┐
│                 Standalone Detection Flow                            │
│                                                                      │
│  1. Check environment variables:                                    │
│     ├─ SDWAN_URL set? → SD-WAN mode (not standalone)               │
│     ├─ CC_URL set? → Catalyst Center mode (not standalone)         │
│     └─ Neither set? → Continue to data model detection             │
│                                                                      │
│  2. Check data model structure:                                     │
│     ├─ "sdwan" key present? → SD-WAN mode                          │
│     ├─ "catalyst_center" key present? → CC mode                    │
│     └─ "devices" key present? → IOSXE mode ✓                  │
│                                                                      │
│  3. StandaloneIOSXEResolver handles device extraction              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Standalone vs Controller-Managed Comparison

| Aspect | Standalone | Controller-Managed |
|--------|------------|-------------------|
| Environment Variables | IOSXE_* only | Controller + IOSXE_* |
| Data Model Key | `devices` | `sdwan` or `catalyst_center` |
| Device Discovery | Direct from YAML | Via controller schema |
| Controller Auth | Not needed | Required for detection |
| Use Case | Direct device access | Production networks |

---

## Complete Test Examples

This section provides complete, production-ready test examples that demonstrate best practices.

### Example: SD-WAN Manager API Test

This example shows a complete API test that verifies device status via the SDWAN Manager controller.

```python
"""
[NRFU]: Verify vManage Device Status
-------------------------------------
Verifies that all managed devices in the SD-WAN fabric are reachable
and in normal operational status according to vManage controller monitoring.

Location: nac-sdwan-terraform/tests/nrfu/verify_vmanage_device_status.py
"""

import time
from pyats import aetest
import jmespath
from nac_test_pyats_common.sdwan import SDWANManagerTestBase
from nac_test.pyats_core.reporting.types import ResultStatus

# Module-level metadata for HTML reports
TITLE = "Verify All Managed Devices Are Reachable and Normal"

DESCRIPTION = """This test validates the operational health and reachability of all managed
devices in the SD-WAN fabric by querying vManage controller device status."""

SETUP = (
    "* Access to an active vManage controller is available via HTTPS API.\n"
    "* Authentication credentials for the vManage controller are valid and configured.\n"
)

PROCEDURE = (
    "* Establish HTTPS connection to the vManage controller.\n"
    "* Query the vManage API endpoint: */dataservice/device/status*.\n"
    "* Verify all critical device types have status='normal'.\n"
)

PASS_FAIL_CRITERIA = (
    "**This test passes when:**\n"
    "* All vSmart, vBond, and vEdge devices have status='normal'.\n"
    "\n"
    "**This test fails if:**\n"
    "* ANY device shows status other than 'normal'.\n"
)


class VerifyVManageDeviceStatus(SDWANManagerTestBase):
    """SD-WAN NRFU test for device health verification."""

    TEST_CONFIG = {
        "resource_type": "vManage Device Status",
        "api_endpoint": "/dataservice/device/status",
        "expected_values": {
            "critical_device_types": ["vSmart", "vbond", "vEdge"],
            "required_status": "normal",
        },
        "log_fields": [
            "check_type",
            "verification_scope",
            "total_device_types",
            "healthy_device_types",
        ],
    }

    @aetest.test
    def test_vmanage_device_status(self, steps):
        """Entry point - delegates to base class orchestration."""
        self.run_async_verification_test(steps)

    def get_items_to_verify(self):
        """Return single context for NRFU discovery-based verification."""
        return [
            {
                "check_type": "vmanage_device_status",
                "verification_scope": "all_managed_devices",
            }
        ]

    async def verify_item(self, semaphore, client, context):
        """Verify all managed devices are healthy via vManage API."""
        async with semaphore:
            try:
                url = self.TEST_CONFIG["api_endpoint"]

                # Build API context for HTML report tracking
                api_context = self.build_api_context(
                    "vManage Device Status",
                    "All Managed Devices",
                    check_type=context.get("check_type"),
                )

                # Make API call with timing
                start_time = time.time()
                response = await client.get(url, test_context=api_context)
                api_duration = time.time() - start_time

                context["api_context"] = api_context

                if response.status_code != 200:
                    return self.format_verification_result(
                        status=ResultStatus.FAILED,
                        context=context,
                        reason=f"API Error: HTTP {response.status_code}",
                        api_duration=api_duration,
                    )

                # Parse and validate response
                data = response.json()
                device_types = jmespath.search("data[*]", data) or []

                critical_types = self.TEST_CONFIG["expected_values"]["critical_device_types"]
                required_status = self.TEST_CONFIG["expected_values"]["required_status"]

                all_healthy = True
                validation_results = []

                for device_type_entry in device_types:
                    device_type = jmespath.search("type", device_type_entry)
                    if device_type not in critical_types:
                        continue

                    total_count = jmespath.search("count", device_type_entry) or 0
                    normal_count = jmespath.search(
                        f"statusList[?status=='{required_status}'] | [0].count",
                        device_type_entry
                    ) or 0

                    if normal_count != total_count:
                        all_healthy = False
                        validation_results.append(
                            f"❌ {device_type}: {normal_count}/{total_count} normal"
                        )
                    else:
                        validation_results.append(
                            f"✅ {device_type}: {normal_count}/{total_count} normal"
                        )

                context["display_context"] = "vManage Device Status -> Device Health"

                if all_healthy:
                    return self.format_verification_result(
                        status=ResultStatus.PASSED,
                        context=context,
                        reason=f"All devices healthy:\n" + "\n".join(validation_results),
                        api_duration=api_duration,
                    )
                else:
                    return self.format_verification_result(
                        status=ResultStatus.FAILED,
                        context=context,
                        reason=f"Unhealthy devices found:\n" + "\n".join(validation_results),
                        api_duration=api_duration,
                    )

            except Exception as e:
                return self.format_verification_result(
                    status=ResultStatus.FAILED,
                    context=context,
                    reason=f"Exception: {str(e)}",
                    api_duration=0,
                )
```

### Example: IOS-XE SSH Test (Architecture-Agnostic)

This example shows a complete SSH test that works across SD-WAN, Catalyst Center, and standalone deployments.

```python
"""
[NRFU]: Verify OSPF Neighbor State
-----------------------------------
Verifies that all OSPF neighbors on devices are in FULL adjacency state.

Location: nac-sdwan-terraform/tests/operational/verify_ospf_neighbor_state.py
(Also works in nac-catalystcenter-terraform with no code changes!)
"""

import time
import jmespath
from pyats import aetest
from nac_test.pyats_core.reporting.types import ResultStatus
from nac_test_pyats_common.iosxe import IOSXETestBase  # Architecture-agnostic!

TITLE = "Verify All OSPF Neighbors Are in FULL State"

DESCRIPTION = """Validates the operational state of all OSPF neighbors.
OSPF neighbors must be in FULL adjacency state for proper routing."""

SETUP = (
    "* SSH access to devices is available.\n"
    "* OSPF is configured and expected to form adjacencies.\n"
)

PROCEDURE = (
    "* Execute 'show ip ospf neighbor detail' on each device.\n"
    "* Parse output using Genie parser.\n"
    "* Verify all neighbors have state='FULL'.\n"
)

PASS_FAIL_CRITERIA = (
    "**This test passes when:**\n"
    "* ALL OSPF neighbors have state 'FULL'.\n"
    "\n"
    "**This test fails if:**\n"
    "* ANY neighbor has state other than 'FULL'.\n"
)


class Test(IOSXETestBase):
    """
    Architecture-agnostic OSPF NRFU test.

    This test automatically works on:
    - SD-WAN deployments (set SDWAN_URL, SDWAN_USERNAME, SDWAN_PASSWORD)
    - Catalyst Center deployments (set CC_URL, CC_USERNAME, CC_PASSWORD)
    - Standalone devices (provide 'devices' key in data model)

    The IOSXETestBase handles architecture detection and device resolution.
    """

    TEST_CONFIG = {
        "resource_type": "OSPF Neighbor",
        "api_endpoint": "show ip ospf neighbor detail",  # CLI command
        "expected_values": {
            "state": "full",  # Genie parser returns lowercase
        },
        "log_fields": [
            "check_type",
            "total_neighbors",
            "full_neighbors",
            "not_full_neighbors",
        ],
    }

    @aetest.test
    def test_ospf_neighbor_state(self, steps):
        """Entry point - delegates to base class orchestration."""
        self.run_async_verification_test(steps)

    def get_items_to_verify(self):
        """Return single context for NRFU discovery-based verification."""
        return [
            {
                "check_type": "ospf_neighbor_state",
                "verification_scope": "all_ospf_neighbors",
            }
        ]

    async def verify_item(self, semaphore, client, context):
        """Verify OSPF neighbor states on the current device."""
        async with semaphore:
            try:
                command = self.TEST_CONFIG["api_endpoint"]

                api_context = self.build_api_context(
                    self.TEST_CONFIG["resource_type"],
                    "All OSPF Neighbors",
                    check_type=context.get("check_type"),
                )

                start_time = time.time()

                # Execute CLI command via SSH (inherited from SSHTestBase)
                with self.test_context(api_context):
                    output = await self.execute_command(command)
                command_duration = time.time() - start_time

                # Parse using Genie parser
                parsed_output = self.parse_output(command, output=output)
                api_duration = command_duration

                context["api_context"] = api_context

                if parsed_output is None:
                    return self.format_verification_result(
                        status=ResultStatus.FAILED,
                        context=context,
                        reason="Failed to parse command output",
                        api_duration=api_duration,
                    )

                # Extract all OSPF neighbors using JMESPath
                all_neighbors = jmespath.search(
                    'vrf.* | [].address_family.* | [].instance.* | '
                    '[].areas.* | [].interfaces.* | [].neighbors.* | []',
                    parsed_output
                ) or []

                if not all_neighbors:
                    context["display_context"] = "OSPF Neighbors -> Adjacency State"
                    return self.format_verification_result(
                        status=ResultStatus.FAILED,
                        context=context,
                        reason="No OSPF neighbors discovered on this device.",
                        api_duration=api_duration,
                    )

                # Validate each neighbor
                expected_state = self.TEST_CONFIG["expected_values"]["state"]
                full_count = 0
                not_full_count = 0
                validation_results = []

                for neighbor in all_neighbors:
                    neighbor_ip = jmespath.search("address", neighbor) or "Unknown"
                    actual_state = jmespath.search("state", neighbor) or "Unknown"

                    if str(actual_state).lower() == expected_state:
                        full_count += 1
                        validation_results.append(f"✅ {neighbor_ip}: {actual_state}")
                    else:
                        not_full_count += 1
                        validation_results.append(f"❌ {neighbor_ip}: {actual_state}")

                context["total_neighbors"] = len(all_neighbors)
                context["full_neighbors"] = full_count
                context["not_full_neighbors"] = not_full_count
                context["display_context"] = "OSPF Neighbors -> Adjacency State"

                if not_full_count == 0:
                    return self.format_verification_result(
                        status=ResultStatus.PASSED,
                        context=context,
                        reason=(
                            f"All {full_count} OSPF neighbors in FULL state:\n"
                            + "\n".join(validation_results)
                        ),
                        api_duration=api_duration,
                    )
                else:
                    return self.format_verification_result(
                        status=ResultStatus.FAILED,
                        context=context,
                        reason=(
                            f"{not_full_count} neighbors NOT in FULL state:\n"
                            + "\n".join(validation_results)
                        ),
                        api_duration=api_duration,
                    )

            except Exception as e:
                context["display_context"] = "OSPF Neighbors -> Adjacency State"
                return self.format_verification_result(
                    status=ResultStatus.FAILED,
                    context=context,
                    reason=f"Exception: {str(e)}",
                    api_duration=0,
                )
```

---

## Contributor Guide

### Adding New Architecture Adapters

To add support for a new controller type (e.g., Meraki):

**1. Create adapter module:**
```
nac_test_pyats_common/
└── meraki/
    ├── __init__.py
    ├── auth.py
    └── test_base.py
```

**2. Implement auth class following two-tier pattern:**
```python
class MerakiAuth:
    @staticmethod
    def _authenticate(url: str, api_key: str) -> tuple[dict, int]:
        """Low-level authentication."""
        ...

    @classmethod
    def get_auth(cls) -> dict[str, Any]:
        """High-level cached auth."""
        ...
```

**3. Implement test base class:**
```python
class MerakiTestBase(NACTestBase):
    @aetest.setup
    def setup(self) -> None:
        super().setup()
        self.auth_data = MerakiAuth.get_auth()
        self.client = self.get_meraki_client()
```

**4. Export from `__init__.py`:**
```python
from .auth import MerakiAuth
from .test_base import MerakiTestBase

__all__ = ["MerakiAuth", "MerakiTestBase"]
```

**5. Add to package `__init__.py`:**
```python
from nac_test_pyats_common.meraki import MerakiAuth, MerakiTestBase
```

### Adding IOS-XE Resolvers

To add a new resolver for IOS-XE devices managed by a different controller:

**1. Create resolver file:**
```python
# iosxe/meraki_resolver.py
from nac_test_pyats_common.common import BaseDeviceResolver
from .registry import register_iosxe_resolver

@register_iosxe_resolver("MERAKI")
class MerakiDeviceResolver(BaseDeviceResolver):
    def get_architecture_name(self) -> str:
        return "meraki"

    def get_schema_root_key(self) -> str:
        return "meraki"

    def navigate_to_devices(self) -> list[dict[str, Any]]:
        return self.data_model.get("meraki", {}).get("devices", [])

    def extract_device_id(self, device_data: dict[str, Any]) -> str:
        return device_data["serial"]

    def extract_hostname(self, device_data: dict[str, Any]) -> str:
        return device_data.get("name", device_data["serial"])

    def extract_host_ip(self, device_data: dict[str, Any]) -> str:
        return device_data["lan_ip"]

    def extract_os_type(self, device_data: dict[str, Any]) -> str:
        return "iosxe"

    def get_credential_env_vars(self) -> tuple[str, str]:
        return ("IOSXE_USERNAME", "IOSXE_PASSWORD")
```

**2. Import in `iosxe/__init__.py` to trigger registration:**
```python
# This import triggers the @register_iosxe_resolver decorator
from . import meraki_resolver  # noqa: F401
```

**3. Update `detect_controller_type()` in nac-test (if needed):**
If the controller uses environment variables, update the controller detection utility.

**Result:** IOSXETestBase automatically supports the new controller type via the registry pattern. No changes needed to IOSXETestBase itself!

---

## Troubleshooting Guide

### Common Issues and Solutions

#### "Missing required credential environment variables"

**Error:**
```
ValueError: Missing required credential environment variables: IOSXE_USERNAME, IOSXE_PASSWORD.
These are required for sdwan D2D testing.
```

**Solution:**
```bash
export IOSXE_USERNAME="admin"
export IOSXE_PASSWORD="your-device-password"
```

**Note:** D2D tests use device credentials (IOSXE_*), not controller credentials (SDWAN_*).

---

#### "Controller type 'X' does not support IOS-XE devices"

**Error:**
```
ValueError: Controller type 'ACI' does not support IOS-XE devices.
Supported types: CC, SDWAN, IOSXE
```

**Cause:** IOSXETestBase only supports controllers that manage IOS-XE devices.

**Solution:** Use a different test base:
- For ACI/APIC: Use `APICTestBase` for API tests
- For NX-OS D2D: Use architecture-specific NX-OS test base (when available)

---

#### "No IOS-XE resolver registered for controller type"

**Error:**
```
ValueError: No device resolver registered for controller type 'MERAKI'
```

**Cause:** The resolver for this controller hasn't been registered.

**Solution:** Either:
1. Use the correct environment variables for a supported controller
2. Implement and register a new resolver (see [Adding IOS-XE Resolvers](#adding-ios-xe-resolvers))

---

#### "Data model missing expected root key"

**Error:**
```
ValueError: Data model missing expected root key 'sdwan' for SDWAN architecture
```

**Cause:** Environment variables indicate SD-WAN, but data model doesn't have `sdwan` key.

**Solution:** Verify:
1. Data files are correct for your architecture
2. Environment variables match your deployment type
3. YAML files are properly formatted and merged

---

#### "Device 'X' from test_inventory not found in data model"

**Warning:**
```
WARNING: Device 'router42' from test_inventory not found in sdwan data model
```

**Cause:** The test_inventory.yaml references a device that doesn't exist in the data model.

**Solution:**
1. Verify device ID in test_inventory matches the data model
2. Check for typos in chassis_id, hostname, or name
3. Ensure the device exists in the NAC configuration files

---

#### Multiple Controllers Detected

**Error:**
```
ValueError: Multiple controller credentials detected: SDWAN, CC. Only one controller type can be active.
```

**Cause:** Environment variables are set for multiple controllers.

**Solution:** Only set credentials for one controller type:
```bash
# Clear unwanted credentials
unset SDWAN_URL SDWAN_USERNAME SDWAN_PASSWORD
# Or
unset CC_URL CC_USERNAME CC_PASSWORD
```

---

### Debug Logging

Enable debug logging to troubleshoot device resolution:

```python
import logging

# Enable debug for resolver operations
logging.getLogger("nac_test_pyats_common").setLevel(logging.DEBUG)

# Enable debug for specific modules
logging.getLogger("nac_test_pyats_common.iosxe.test_base").setLevel(logging.DEBUG)
logging.getLogger("nac_test_pyats_common.common.base_device_resolver").setLevel(logging.DEBUG)
```

**Debug output includes:**
- Detected controller type
- Number of devices found in data model
- Devices matched from test_inventory
- Credential injection confirmation
- Final resolved device count

---

## Document Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01-07 | Initial comprehensive documentation |

---

## References

- **nac-test PRD:** `/home/administrator/Net-As-Code/nac-test/dev-docs/PRD_AND_ARCHITECTURE.md`
- **BaseDeviceResolver:** `nac-test-pyats-common/src/nac_test_pyats_common/common/base_device_resolver.py`
- **Controller Detection:** `nac-test/nac_test/utils/controller.py`
