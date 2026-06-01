[![Tests](https://github.com/netascode/nac-test-pyats-common/actions/workflows/test.yml/badge.svg)](https://github.com/netascode/nac-test-pyats-common/actions/workflows/test.yml)
![Python Support](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-informational "Python Support: 3.10, 3.11, 3.12")

# nac-test-pyats-common

> **⚠️ INITIAL DEVELOPMENT**: This package is under active initial development and not yet ready for production use.

A shared library consolidating duplicated PyATS testing infrastructure across NAC (Network as Code) architecture repositories. This package serves as a Layer 2 adapter between architecture-specific test repositories (ACI, SD-WAN, Catalyst Center) and the core nac-test framework.

## Overview

The `nac-test-pyats-common` package addresses the architectural challenge of duplicated `pyats_common/` directories across NAC architecture repositories. It consolidates shared PyATS testing infrastructure—including authentication classes, test base classes, and device resolvers—into a centralized, maintainable package.

### Problem Solved

Each NAC architecture repository previously contained duplicated PyATS infrastructure code:
- ~90% of base test class code was identical across architectures
- Bug fixes and improvements required manual propagation to all repos
- Each architecture team maintained essentially the same code
- Adding new architectures (ISE, Meraki, IOS-XE) compounded the duplication problem

### Solution Architecture

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
│       Layer 2: nac-test-pyats-common (Architecture Adapters)        │
│                    DEPENDS ON nac-test                               │
│                                                                      │
│  • Architecture-specific authentication (APICAuth, VManageAuth)      │
│  • Architecture-specific test base classes (APICTestBase, etc.)      │
│  • Architecture-specific device resolvers (SDWANDeviceResolver)      │
│                       │                                              │
│                       │ imports NACTestBase, SSHTestBase, AuthCache │
│                       ▼                                              │
└───────────────────────┼──────────────────────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────────────────────┐
│                Layer 1: nac-test (Core Framework)                    │
│                    Orchestration + Generic Infrastructure            │
│                                                                      │
│  • Test orchestration (discovering tests, running them)              │
│  • Testbed generation (generic device dict → PyATS YAML)            │
│  • Connection brokering (SSH connection pooling)                     │
│  • HTML report generation                                            │
│  • Generic base classes (NACTestBase, SSHTestBase)                  │
└─────────────────────────────────────────────────────────────────────┘
```

## Supported Architectures

### Currently Supported
- **ACI (Application Centric Infrastructure)**
  - `APICAuth` - APIC authentication with cookie-based sessions
  - `APICTestBase` - Base class for ACI/APIC tests
  - `ACIDeviceResolver` - Device inventory from ACI data models

- **SD-WAN**
  - `VManageAuth` - vManage authentication with token-based sessions
  - `VManageTestBase` - Base class for vManage API tests
  - `SDWANSSHTestBase` - Base class for SD-WAN D2D/SSH tests
  - `SDWANDeviceResolver` - Device inventory from sites.nac.yaml

- **Catalyst Center**
  - `CatalystCenterAuth` - Token-based authentication (X-Auth-Token)
  - `CatalystCenterTestBase` - Base class for Catalyst Center API tests
  - `CatalystCenterDeviceResolver` - Device inventory from NAC schemas

### Planned Support
- ISE (Identity Services Engine)
- Meraki
- IOS-XE (Direct device access)

## Installation

Python 3.10+ is required. Don't have Python 3.10 or later? See [Python 3 Installation & Setup Guide](https://realpython.com/installing-python/).

```shell
pip install nac-test-pyats-common
```

This will automatically install the required dependencies:
- `nac-test~=1.1.0` - Core testing framework (brings PyATS as transitive dependency)
- `httpx>=0.28` - HTTP client for authentication

## Usage

### Import Pattern

Replace the old fragile imports from architecture repos:

```python
# Old pattern (remove this)
from templates.catc.test.pyats_common.catc_base_test import CatalystCenterTestBase

# New pattern (use this)
from nac_test_pyats_common.catc import CatalystCenterTestBase
```

### Example Test File

```python
# In nac-catalystcenter-terraform/tests/templates/catc/test/api/verify_something.py

from nac_test_pyats_common.catc import CatalystCenterTestBase
from nac_test.pyats_core.reporting.types import ResultStatus
from pyats import aetest

class TestCatalystCenterFeature(CatalystCenterTestBase):
    """Test class for Catalyst Center feature verification."""

    @aetest.test
    def verify_feature(self):
        """Verify feature configuration."""
        # self.client is already configured with auth headers
        response = self.client.get("/api/v1/feature")

        if response.status_code == 200:
            self.result = ResultStatus.PASS
        else:
            self.result = ResultStatus.FAIL
```

## API Structure

### Authentication Classes

Each architecture provides an authentication class that handles controller-specific authentication:

```python
from nac_test_pyats_common.aci import APICAuth
from nac_test_pyats_common.sdwan import VManageAuth
from nac_test_pyats_common.catc import CatalystCenterAuth

# Authentication is handled automatically when using test base classes
# But can be used directly if needed:
auth_data = CatalystCenterAuth.get_auth()  # Uses AuthCache internally
```

### Test Base Classes

Test base classes extend `NACTestBase` from nac-test with architecture-specific setup:

```python
from nac_test_pyats_common.catc import CatalystCenterTestBase

class MyTest(CatalystCenterTestBase):
    """Your test class."""

    @aetest.setup
    def setup(self):
        """Setup is handled by base class."""
        super().setup()
        # self.client is now available with auth headers configured
        # self.auth_data contains authentication tokens/cookies
```

### Device Resolvers

Device resolvers parse NAC schemas to provide device inventory for SSH tests:

```python
from nac_test_pyats_common.sdwan import SDWANDeviceResolver

# Used by nac-test orchestrator internally
devices = SDWANDeviceResolver.get_ssh_device_inventory(data_model)
```

## Environment Variables

Each architecture requires specific environment variables for authentication:

### Catalyst Center
- `CC_URL` - Controller URL
- `CC_USERNAME` - Username
- `CC_PASSWORD` - Password
- `CC_INSECURE` - Skip SSL verification (optional, default: "True")

### SD-WAN

**Session auth (username/password):**
- `SDWAN_URL` - SD-WAN Manager URL
- `SDWAN_USERNAME` - Username
- `SDWAN_PASSWORD` - Password
- `SDWAN_INSECURE` - Skip SSL verification (optional, default: "True")

**Token auth (20.18+):**
- `SDWAN_URL` - SD-WAN Manager URL
- `SDWAN_API_TOKEN` - API token (JWT) for Bearer authentication

The auth method is determined automatically by nac-test's credential set detection.
If `SDWAN_API_TOKEN` is set (and `SDWAN_URL`), token auth is used — the JWT payload
is decoded to extract the CSRF token, which is sent as the `X-XSRF-TOKEN` header
alongside `Authorization: Bearer`. Otherwise, username/password session auth is used.

### ACI
- `APIC_URL` - APIC URL
- `APIC_USERNAME` - Username
- `APIC_PASSWORD` - Password
- `APIC_INSECURE` - Skip SSL verification (optional, default: "True")

## Development

### Local Development Setup

```bash
# Clone the repository
git clone https://github.com/netascode/nac-test-pyats-common.git
cd nac-test-pyats-common

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/unit/ -v
pytest tests/integration/ -v  # Requires nac-test

# Type checking
mypy --strict src/

# Linting
ruff check src/
```

### Contributing

When contributing, understand which repository to modify:

| Change Type | Repository | Example |
|-------------|------------|---------|
| Auth endpoint change | nac-test-pyats-common | Catalyst Center adds new auth API |
| Test base setup logic | nac-test-pyats-common | Add new setup step for all CC tests |
| Generic orchestration | nac-test | Change how tests are discovered/run |
| HTML report format | nac-test | Modify report template |
| Test file (verify_*.py) | Architecture repo | Add new verification test |

## Dependencies

- `nac-test~=1.1.0` - Core testing framework
  - Provides: `NACTestBase`, `SSHTestBase`, `AuthCache`, orchestration
  - Brings PyATS as transitive dependency
- `httpx>=0.28` - Modern async-capable HTTP client

## Versioning

This package follows [Semantic Versioning 2.0.0](https://semver.org/):
- **MAJOR**: Breaking API changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

### Compatibility Matrix

| nac-test-pyats-common | nac-test Required | Notes |
|-----------------------|-------------------|-------|
| 1.0.x | ~=1.1.0 | Initial release |
| 1.1.x | ~=1.1.0 | New architecture added |
| 2.0.x | ~=2.0.0 | Breaking changes |

## License

This project is licensed under the Mozilla Public License 2.0 (MPL-2.0) - see the [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/netascode/nac-test-pyats-common).