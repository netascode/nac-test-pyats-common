# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0b1] - 2026-09-09

### Added

- **NX-OS Architecture Adapter** ([#41](https://github.com/netascode/nac-test-pyats-common/pull/41))
  - `NXOSDeviceResolver` for D2D SSH device resolution from `nxos.devices[]` schema
  - `NXOSTestBase` for NX-OS SSH/D2D operational testing with learning mode support
- **SD-WAN Data Model Device Helper** ([#37](https://github.com/netascode/nac-test-pyats-common/pull/37))
  - Added `get_devices_from_data_model()` to `SDWANManagerTestBase` to extract `system_ip`, `site_id`, and `hostname` from NaC SD-WAN schema (`sdwan.sites[].routers[].device_variables`)
- **SD-WAN Token Authentication Support** ([#33](https://github.com/netascode/nac-test-pyats-common/pull/33))
  - Token-based authentication for SD-WAN Manager 20.18+ (`SDWAN_API_TOKEN` with JWT-derived CSRF / `X-XSRF-TOKEN` header)
  - Automatic dual-mode authentication via `nac-test` controller resolution
  - Legacy session-based authentication remains supported

### Changed

- **Controller Resolution via nac-test Core Resolvers** ([#46](https://github.com/netascode/nac-test-pyats-common/pull/46))
  - Replaced direct environment variable reads and hardcoded auth logic with `nac-test` core controller resolvers (`get_controller_context`, `get_connection_params`, `should_verify_ssl`)
  - Added `EXPECTED_CONTROLLER_TYPE` and `SUPPORTED_AUTH_METHODS` guards across ACI, Catalyst Center, and SD-WAN `TestBase` classes
  - Parameterized `get_token()`, `get_token_auth()`, and `get_session_auth()` so `TestBase` instances use parent-resolved credentials directly
  - Upgraded minimum `nac-test` dependency to `2.1.0b1`

### Fixed

- Passed `verify_ssl` to ACI authentication POST for consistency with other adapters ([#46](https://github.com/netascode/nac-test-pyats-common/pull/46))

## [0.3.0] - 2026-03-10

### Fixed

- **SD-WAN Authentication Hardening** ([#29](https://github.com/netascode/nac-test-pyats-common/pull/29))
  - Detected HTML login page responses returned by SD-WAN Manager on authentication failure (HTTP 200 with HTML body) instead of silently succeeding with invalid sessions
  - Categorized error taxonomy distinguishing credential errors (401/403/HTML login) from server errors (500+) and network errors
  - Added defense-in-depth validation for XSRF token endpoint (rejecting HTML and empty bodies)
- **SD-WAN UX 2.0 Hostname Resolution** ([#31](https://github.com/netascode/nac-test-pyats-common/pull/31))
  - Added support for `host_name` field (UX 2.0 configuration groups) alongside `system_hostname` (UX 1.0) in `extract_hostname()`

## [0.2.2] - 2026-02-18

### Fixed

- **ACI Environment Variable Naming** ([#27](https://github.com/netascode/nac-test-pyats-common/pull/27))
  - Aligned environment variable names in `APICAuth.get_auth()` from `APIC_*` to `ACI_*` (`ACI_URL`, `ACI_USERNAME`, `ACI_PASSWORD`, `ACI_INSECURE`) to match the `nac-test` controller registry

## [0.2.1] - 2026-02-03

### Added

- **PyATS Abstraction Fields Support** ([#11](https://github.com/netascode/nac-test-pyats-common/pull/11))
  - Enhanced device resolver with `extract_os_platform_type()` returning `os`, `platform`, `model`, and `series`
  - `SDWANDeviceResolver` returns `{"os": "iosxe", "platform": "sdwan"}` to optimize PyATS/Genie parser selection
- **Subprocess Authentication Architecture** ([#21](https://github.com/netascode/nac-test-pyats-common/pull/21))
  - Fork-safe authentication via subprocess (`execute_auth_subprocess`) across ACI, SD-WAN, and Catalyst Center adapters to resolve macOS OpenSSL/httpx fork crashes
  - Added `verify_ssl` parameter and `SDWAN_INSECURE` / `ACI_INSECURE` support
  - Deferred `httpx.AsyncClient` creation to `run_async_verification_test()` inside the event loop context

### Changed

- Injected environment variable references (`%ENV{VARNAME}`) into device dictionaries instead of cleartext credentials, resolved natively by PyATS testbed loader ([#13](https://github.com/netascode/nac-test-pyats-common/pull/13))
- Renamed `extract_os_type()` to `extract_os_platform_type()` on `BaseDeviceResolver` ([#11](https://github.com/netascode/nac-test-pyats-common/pull/11))

## [0.2.0] - 2025-01-27

### Added

- **Catalyst Center D2D Testing Support** ([#6](https://github.com/netascode/nac-test-pyats-common/pull/6))
  - `CatalystCenterDeviceResolver` for D2D SSH testing via `catalyst_center.inventory.devices[]` schema
  - Device state validation (skips devices in INIT/PNP states)
  - Comprehensive unit tests for device resolver and auth modules

- **SD-WAN Cascading Management IP Variable Lookup** ([#3](https://github.com/netascode/nac-test-pyats-common/pull/3))
  - Router-level `management_ip_variable` override support
  - Falls back to global `sdwan.management_ip_variable` when not set at router level
  - `skipped_devices` tracking replaces deprecated `test_inventory`
  - Exposed `_last_resolver` for accessing skip reasons

- **BaseDeviceResolver Improvements** ([#9](https://github.com/netascode/nac-test-pyats-common/pull/9))
  - `extract_device_id()` is now optional with sensible default (delegates to `extract_hostname()`)
  - Added IP address validation after CIDR stripping using Python's `ipaddress` module
  - Descriptive error messages for malformed IP addresses

### Changed

- Removed redundant `extract_device_id()` from `CatalystCenterDeviceResolver` (now uses inherited default)

### Fixed

- Dependabot configured to ignore `nac-test` until beta branch merges ([#9](https://github.com/netascode/nac-test-pyats-common/pull/9))

## [0.1.1] - 2025-01-24

### Changed

- Version bump only (no functional changes)

## [0.1.0] - 2025-01-23

### Added

- **Core Package Structure**
  - Type-safe Python package with py.typed marker
  - Pre-commit hooks and GitHub Actions CI/CD

- **ACI/APIC Architecture Adapter**
  - `APICAuth` for APIC controller authentication
  - `APICTestBase` base class for APIC API tests

- **SD-WAN Architecture Adapter**
  - `SDWANManagerAuth` for SD-WAN Manager authentication
  - `SDWANManagerTestBase` for controller API tests
  - `SDWANTestBase` for device tests
  - `SDWANDeviceResolver` for D2D testing via `sdwan.sites[].routers[]` schema

- **Base Device Resolver**
  - Template Method pattern for architecture-specific device resolution
  - Credential injection from environment variables
  - CIDR notation handling for IP addresses

- **IOS-XE Integration**
  - `IOSXETestBase` with architecture auto-detection
  - Resolver registry for dynamic architecture selection

[0.4.0]: https://github.com/netascode/nac-test-pyats-common/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/netascode/nac-test-pyats-common/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/netascode/nac-test-pyats-common/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/netascode/nac-test-pyats-common/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/netascode/nac-test-pyats-common/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/netascode/nac-test-pyats-common/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/netascode/nac-test-pyats-common/releases/tag/v0.1.0
