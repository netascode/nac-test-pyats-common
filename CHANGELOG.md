# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.0]: https://github.com/netascode/nac-test-pyats-common/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/netascode/nac-test-pyats-common/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/netascode/nac-test-pyats-common/releases/tag/v0.1.0
