# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for BaseDeviceResolver abstract base class.

This module tests the base device resolver functionality including:
- Device dictionary building and validation
- Credential injection from environment variables
- Full resolution flow
"""

from typing import Any
from unittest.mock import patch

import pytest

from nac_test_pyats_common.common.base_device_resolver import BaseDeviceResolver


class MockDeviceResolver(BaseDeviceResolver):
    """Concrete implementation of BaseDeviceResolver for testing.

    This mock implementation provides simple implementations of all
    abstract methods for testing the base class functionality.
    """

    def get_architecture_name(self) -> str:
        """Return mock architecture name."""
        return "mock_arch"

    def get_schema_root_key(self) -> str:
        """Return mock schema root key."""
        return "mock"

    def navigate_to_devices(self) -> list[dict[str, Any]]:
        """Navigate to devices in the data model."""
        return self.data_model.get("mock", {}).get("devices", [])  # type: ignore[no-any-return]

    def extract_device_id(self, device_data: dict[str, Any]) -> str:
        """Extract device ID from device data."""
        return device_data["device_id"]  # type: ignore[no-any-return]

    def extract_hostname(self, device_data: dict[str, Any]) -> str:
        """Extract hostname from device data."""
        return device_data["hostname"]  # type: ignore[no-any-return]

    def extract_host_ip(self, device_data: dict[str, Any]) -> str:
        """Extract IP address from device data."""
        return device_data["host"]  # type: ignore[no-any-return]

    def extract_os_type(self, device_data: dict[str, Any]) -> str:
        """Extract OS type from device data."""
        return device_data["os"]  # type: ignore[no-any-return]

    def get_credential_env_vars(self) -> tuple[str, str]:
        """Return environment variable names for credentials."""
        return ("MOCK_USERNAME", "MOCK_PASSWORD")


@pytest.fixture  # type: ignore[untyped-decorator]
def sample_data_model() -> dict[str, Any]:
    """Provide a sample data model for testing."""
    return {
        "mock": {
            "devices": [
                {
                    "device_id": "device1",
                    "hostname": "router1",
                    "host": "10.1.1.1",
                    "os": "iosxe",
                },
                {
                    "device_id": "device2",
                    "hostname": "router2",
                    "host": "10.1.1.2",
                    "os": "nxos",
                },
                {
                    "device_id": "device3",
                    "hostname": "router3",
                    "host": "10.1.1.3",
                    "os": "iosxr",
                },
            ]
        }
    }


@pytest.fixture  # type: ignore[untyped-decorator]
def mock_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set mock credential environment variables."""
    monkeypatch.setenv("MOCK_USERNAME", "test_user")
    monkeypatch.setenv("MOCK_PASSWORD", "test_pass")


class TestCredentialInjection:
    """Test credential injection from environment variables."""

    def test_successful_credential_injection(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test successful injection of credentials from environment variables."""
        resolver = MockDeviceResolver(sample_data_model)
        devices = resolver.get_resolved_inventory()

        for device in devices:
            assert device["username"] == "test_user"
            assert device["password"] == "test_pass"

    def test_error_when_username_env_var_missing(
        self,
        sample_data_model: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test ValueError raised when username environment variable is missing."""
        monkeypatch.setenv("MOCK_PASSWORD", "test_pass")
        # MOCK_USERNAME is not set

        resolver = MockDeviceResolver(sample_data_model)

        with pytest.raises(ValueError) as exc_info:
            resolver.get_resolved_inventory()

        assert "MOCK_USERNAME" in str(exc_info.value)
        assert "Missing required credential environment variables" in str(
            exc_info.value
        )

    def test_error_when_password_env_var_missing(
        self,
        sample_data_model: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test ValueError raised when password environment variable is missing."""
        monkeypatch.setenv("MOCK_USERNAME", "test_user")
        # MOCK_PASSWORD is not set

        resolver = MockDeviceResolver(sample_data_model)

        with pytest.raises(ValueError) as exc_info:
            resolver.get_resolved_inventory()

        assert "MOCK_PASSWORD" in str(exc_info.value)
        assert "Missing required credential environment variables" in str(
            exc_info.value
        )

    def test_error_message_includes_architecture_name(
        self,
        sample_data_model: dict[str, Any],
    ) -> None:
        """Test that credential error message includes the architecture name."""
        # No credentials set
        resolver = MockDeviceResolver(sample_data_model)

        with pytest.raises(ValueError) as exc_info:
            resolver.get_resolved_inventory()

        assert "mock_arch D2D testing" in str(exc_info.value)

    def test_both_credentials_missing_lists_both(
        self,
        sample_data_model: dict[str, Any],
    ) -> None:
        """Test that both missing credentials are listed in error message."""
        # No credentials set
        resolver = MockDeviceResolver(sample_data_model)

        with pytest.raises(ValueError) as exc_info:
            resolver.get_resolved_inventory()

        error_msg = str(exc_info.value)
        assert "MOCK_USERNAME" in error_msg
        assert "MOCK_PASSWORD" in error_msg
        assert "MOCK_USERNAME, MOCK_PASSWORD" in error_msg


class TestBuildDeviceDict:
    """Test device dictionary building and validation."""

    def test_successful_device_dict_building(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test successful building of device dictionary."""
        resolver = MockDeviceResolver(sample_data_model)
        device_data = sample_data_model["mock"]["devices"][0]

        device_dict = resolver.build_device_dict(device_data)

        assert device_dict["hostname"] == "router1"
        assert device_dict["host"] == "10.1.1.1"
        assert device_dict["os"] == "iosxe"
        assert device_dict["device_id"] == "device1"

    def test_validation_catches_empty_hostname(
        self,
        sample_data_model: dict[str, Any],
    ) -> None:
        """Test that validation catches empty hostname."""
        resolver = MockDeviceResolver(sample_data_model)
        device_data = {
            "device_id": "device1",
            "hostname": "",  # Empty hostname
            "host": "10.1.1.1",
            "os": "iosxe",
        }

        with pytest.raises(ValueError) as exc_info:
            resolver.build_device_dict(device_data)

        assert "Invalid hostname" in str(exc_info.value)

    def test_validation_catches_empty_host(
        self,
        sample_data_model: dict[str, Any],
    ) -> None:
        """Test that validation catches empty host IP."""
        resolver = MockDeviceResolver(sample_data_model)
        device_data = {
            "device_id": "device1",
            "hostname": "router1",
            "host": "",  # Empty host
            "os": "iosxe",
        }

        with pytest.raises(ValueError) as exc_info:
            resolver.build_device_dict(device_data)

        assert "Invalid host IP" in str(exc_info.value)

    def test_validation_catches_empty_os(
        self,
        sample_data_model: dict[str, Any],
    ) -> None:
        """Test that validation catches empty OS type."""
        resolver = MockDeviceResolver(sample_data_model)
        device_data = {
            "device_id": "device1",
            "hostname": "router1",
            "host": "10.1.1.1",
            "os": "",  # Empty OS
        }

        with pytest.raises(ValueError) as exc_info:
            resolver.build_device_dict(device_data)

        assert "Invalid OS type" in str(exc_info.value)

    def test_validation_catches_empty_device_id(
        self,
        sample_data_model: dict[str, Any],
    ) -> None:
        """Test that validation catches empty device ID."""
        resolver = MockDeviceResolver(sample_data_model)
        device_data = {
            "device_id": "",  # Empty device ID
            "hostname": "router1",
            "host": "10.1.1.1",
            "os": "iosxe",
        }

        with pytest.raises(ValueError) as exc_info:
            resolver.build_device_dict(device_data)

        assert "Invalid device ID" in str(exc_info.value)

    def test_validation_catches_none_values(
        self,
        sample_data_model: dict[str, Any],
    ) -> None:
        """Test that validation catches None values in required fields."""
        resolver = MockDeviceResolver(sample_data_model)

        # Test None hostname
        device_data = {
            "device_id": "device1",
            "hostname": None,
            "host": "10.1.1.1",
            "os": "iosxe",
        }

        # Mock the extract methods to return None
        with patch.object(resolver, "extract_hostname", return_value=None):
            with pytest.raises(ValueError) as exc_info:
                resolver.build_device_dict(device_data)
            assert "Invalid hostname: None" in str(exc_info.value)

    def test_skips_device_with_invalid_data(
        self,
        mock_credentials: None,
    ) -> None:
        """Test that devices with invalid data are skipped and tracked."""
        data_model = {
            "mock": {
                "devices": [
                    {
                        "device_id": "device1",
                        "hostname": "router1",
                        "host": "10.1.1.1",
                        "os": "iosxe",
                    },
                    {
                        "device_id": "device2",
                        "hostname": "",  # Invalid
                        "host": "10.1.1.2",
                        "os": "nxos",
                    },
                    {
                        "device_id": "device3",
                        "hostname": "router3",
                        "host": "10.1.1.3",
                        "os": "iosxr",
                    },
                ]
            }
        }

        resolver = MockDeviceResolver(data_model)
        devices = resolver.get_resolved_inventory()

        # Should only get 2 valid devices
        assert len(devices) == 2
        device_ids = [d["device_id"] for d in devices]
        assert "device1" in device_ids
        assert "device3" in device_ids
        assert "device2" not in device_ids

        # Check skipped_devices tracking
        assert len(resolver.skipped_devices) == 1
        assert resolver.skipped_devices[0]["device_id"] == "device2"
        assert "hostname" in resolver.skipped_devices[0]["reason"].lower()


class TestFullResolutionFlow:
    """Test the complete device resolution flow."""

    def test_get_resolved_inventory_returns_all_devices(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test that get_resolved_inventory returns all devices from data model."""
        resolver = MockDeviceResolver(sample_data_model)
        devices = resolver.get_resolved_inventory()

        assert len(devices) == 3
        device_ids = [d["device_id"] for d in devices]
        assert "device1" in device_ids
        assert "device2" in device_ids
        assert "device3" in device_ids

    def test_get_resolved_inventory_returns_properly_formatted_devices(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test that get_resolved_inventory returns properly formatted devices."""
        resolver = MockDeviceResolver(sample_data_model)
        devices = resolver.get_resolved_inventory()

        # Check first device
        device1 = next(d for d in devices if d["device_id"] == "device1")
        assert device1["hostname"] == "router1"
        assert device1["host"] == "10.1.1.1"
        assert device1["os"] == "iosxe"
        assert device1["username"] == "test_user"
        assert device1["password"] == "test_pass"
        assert device1["device_id"] == "device1"

        # Check third device
        device3 = next(d for d in devices if d["device_id"] == "device3")
        assert device3["hostname"] == "router3"
        assert device3["host"] == "10.1.1.3"
        assert device3["os"] == "iosxr"
        assert device3["username"] == "test_user"
        assert device3["password"] == "test_pass"
        assert device3["device_id"] == "device3"

    def test_devices_have_all_required_fields(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test that all resolved devices have required fields."""
        resolver = MockDeviceResolver(sample_data_model)
        devices = resolver.get_resolved_inventory()

        required_fields = [
            "hostname",
            "host",
            "os",
            "username",
            "password",
            "device_id",
        ]

        for device in devices:
            for field in required_fields:
                assert field in device
                assert device[field] is not None
                assert device[field] != ""

    def test_logging_output(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test that appropriate logging is produced during resolution."""
        with caplog.at_level("INFO"):
            resolver = MockDeviceResolver(sample_data_model)
            _ = resolver.get_resolved_inventory()

        # Check for key log messages
        assert "Resolving device inventory for mock_arch" in caplog.text
        assert "Resolved 3 devices for mock_arch D2D testing" in caplog.text


class TestAbstractMethods:
    """Test that abstract methods are properly enforced."""

    def test_cannot_instantiate_base_class(self) -> None:
        """Test that BaseDeviceResolver cannot be instantiated directly."""
        with pytest.raises(TypeError) as exc_info:
            BaseDeviceResolver({})  # type: ignore[abstract]

        assert "Can't instantiate abstract class" in str(exc_info.value)

    def test_all_abstract_methods_must_be_implemented(self) -> None:
        """Test that all abstract methods must be implemented in subclass."""

        class IncompleteResolver(BaseDeviceResolver):
            """Resolver missing some abstract method implementations."""

            def get_architecture_name(self) -> str:
                return "incomplete"

            def get_schema_root_key(self) -> str:
                return "incomplete"

            # Missing: navigate_to_devices, extract_device_id, etc.

        with pytest.raises(TypeError) as exc_info:
            IncompleteResolver({})  # type: ignore[abstract]

        assert "Can't instantiate abstract class" in str(exc_info.value)


class TestOptionalOverrides:
    """Test optional method overrides."""

    def test_custom_build_device_dict(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test overriding build_device_dict to add custom fields."""

        class CustomResolver(MockDeviceResolver):
            def build_device_dict(self, device_data: dict[str, Any]) -> dict[str, Any]:
                # Call parent implementation
                device_dict: dict[str, Any] = super().build_device_dict(device_data)

                # Add custom fields
                device_dict["custom_field"] = "custom_value"
                device_dict["site_id"] = device_data.get("site_id", "unknown")

                return device_dict

        resolver = CustomResolver(sample_data_model)
        devices = resolver.get_resolved_inventory()

        for device in devices:
            assert device["custom_field"] == "custom_value"
            assert "site_id" in device


class TestDeviceValidation:
    """Test the validate_device_data hook."""

    def test_default_validation_accepts_all_devices(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test that default validation accepts all devices."""
        resolver = MockDeviceResolver(sample_data_model)
        devices = resolver.get_resolved_inventory()

        # All 3 devices from sample_data_model should be resolved
        assert len(devices) == 3
        assert len(resolver.skipped_devices) == 0

    def test_custom_validation_can_skip_devices(
        self,
        mock_credentials: None,
    ) -> None:
        """Test that custom validation can skip specific devices."""

        class ValidatingResolver(MockDeviceResolver):
            def validate_device_data(self, device_data: dict[str, Any]) -> None:
                # Skip devices with specific site_id
                if device_data.get("site_id") == "skip-me":
                    raise ValueError("Device at skip-me site should be skipped")

        data_model = {
            "mock": {
                "devices": [
                    {
                        "device_id": "device1",
                        "hostname": "host1",
                        "host": "10.1.1.1",
                        "os": "iosxe",
                        "site_id": "keep-me",
                    },
                    {
                        "device_id": "device2",
                        "hostname": "host2",
                        "host": "10.1.1.2",
                        "os": "iosxe",
                        "site_id": "skip-me",
                    },
                    {
                        "device_id": "device3",
                        "hostname": "host3",
                        "host": "10.1.1.3",
                        "os": "iosxe",
                        "site_id": "keep-me",
                    },
                ]
            }
        }

        resolver = ValidatingResolver(data_model)
        devices = resolver.get_resolved_inventory()

        # Only 2 devices should be resolved (skipping device2)
        assert len(devices) == 2
        assert len(resolver.skipped_devices) == 1
        assert resolver.skipped_devices[0]["device_id"] == "device2"
        assert "skip-me" in resolver.skipped_devices[0]["reason"]

    def test_validation_called_before_extraction(
        self,
        mock_credentials: None,
    ) -> None:
        """Test that validation is called before field extraction."""
        call_order: list[str] = []

        class OrderTrackingResolver(MockDeviceResolver):
            def validate_device_data(self, device_data: dict[str, Any]) -> None:
                call_order.append("validate")

            def extract_device_id(self, device_data: dict[str, Any]) -> str:
                call_order.append("extract_id")
                return super().extract_device_id(device_data)

        data_model = {
            "mock": {
                "devices": [
                    {
                        "device_id": "device1",
                        "hostname": "host1",
                        "host": "10.1.1.1",
                        "os": "iosxe",
                    },
                ]
            }
        }

        resolver = OrderTrackingResolver(data_model)
        resolver.get_resolved_inventory()

        # Validation should be called before extraction
        assert len(call_order) >= 2
        validate_index = call_order.index("validate")
        extract_index = call_order.index("extract_id")
        assert validate_index < extract_index


class TestErrorHandling:
    """Test error handling in various scenarios."""

    def test_handles_missing_device_fields_gracefully(
        self,
        mock_credentials: None,
    ) -> None:
        """Test that missing required fields are handled gracefully."""

        class ErrorResolver(MockDeviceResolver):
            def extract_hostname(self, device_data: dict[str, Any]) -> str:
                # Simulate KeyError for some devices
                if device_data.get("device_id") == "device2":
                    raise KeyError("hostname")
                return super().extract_hostname(device_data)

        data_model = {
            "mock": {
                "devices": [
                    {
                        "device_id": "device1",
                        "hostname": "router1",
                        "host": "10.1.1.1",
                        "os": "iosxe",
                    },
                    {
                        "device_id": "device2",
                        "hostname": "router2",
                        "host": "10.1.1.2",
                        "os": "nxos",
                    },
                ]
            }
        }

        resolver = ErrorResolver(data_model)
        devices = resolver.get_resolved_inventory()

        # Should only get device1, device2 should be skipped
        assert len(devices) == 1
        assert devices[0]["device_id"] == "device1"

        # Check skipped_devices tracking for device2
        assert len(resolver.skipped_devices) == 1
        assert resolver.skipped_devices[0]["device_id"] == "device2"
        assert "'hostname'" in resolver.skipped_devices[0]["reason"]

    def test_safe_extract_device_id(
        self,
        sample_data_model: dict[str, Any],
    ) -> None:
        """Test that _safe_extract_device_id handles extraction errors."""

        class ErrorResolver(MockDeviceResolver):
            def extract_device_id(self, device_data: dict[str, Any]) -> str:
                if "error" in device_data:
                    raise KeyError("device_id")
                return super().extract_device_id(device_data)

        resolver = ErrorResolver(sample_data_model)

        # Should return "<unknown>" when no fallback fields available
        result = resolver._safe_extract_device_id({"error": True})
        assert result == "<unknown>"

        # Should fallback to 'name' field if extract_device_id fails
        result = resolver._safe_extract_device_id({"error": True, "name": "device-abc"})
        assert result == "device-abc"

        # Should return actual ID for valid case
        result = resolver._safe_extract_device_id({"device_id": "test123"})
        assert result == "test123"

    def test_empty_data_model_returns_empty_list(
        self,
        mock_credentials: None,
    ) -> None:
        """Test that empty data model returns empty device list."""
        resolver = MockDeviceResolver({})
        devices = resolver.get_resolved_inventory()

        assert devices == []

    def test_missing_devices_key_returns_empty_list(
        self,
        mock_credentials: None,
    ) -> None:
        """Test that missing devices key returns empty device list."""
        resolver = MockDeviceResolver({"mock": {}})
        devices = resolver.get_resolved_inventory()

        assert devices == []


class TestSkippedDevicesTracking:
    """Test that skipped devices are tracked properly."""

    def test_skipped_devices_list_initialized_empty(
        self,
        sample_data_model: dict[str, Any],
    ) -> None:
        """Test that skipped_devices is initialized as empty list."""
        resolver = MockDeviceResolver(sample_data_model)
        assert resolver.skipped_devices == []

    def test_skipped_devices_populated_on_resolution_failure(
        self,
        mock_credentials: None,
    ) -> None:
        """Test that skipped_devices is populated when device resolution fails."""
        data_model = {
            "mock": {
                "devices": [
                    {
                        "device_id": "device1",
                        "hostname": "router1",
                        "host": "10.1.1.1",
                        "os": "iosxe",
                    },
                    {
                        "device_id": "device2",
                        "hostname": "",  # Invalid - will be skipped
                        "host": "10.1.1.2",
                        "os": "nxos",
                    },
                    {
                        "device_id": "device3",
                        "hostname": "router3",
                        "host": "",  # Invalid - will be skipped
                        "os": "iosxr",
                    },
                ]
            }
        }

        resolver = MockDeviceResolver(data_model)
        devices = resolver.get_resolved_inventory()

        # Should only get 1 valid device
        assert len(devices) == 1
        assert devices[0]["device_id"] == "device1"

        # Should have 2 skipped devices
        assert len(resolver.skipped_devices) == 2

        # Check skipped device info
        skipped_ids = [s["device_id"] for s in resolver.skipped_devices]
        assert "device2" in skipped_ids
        assert "device3" in skipped_ids

        # Check that reasons are captured
        for skip_info in resolver.skipped_devices:
            assert "reason" in skip_info
            assert skip_info["reason"] != ""

    def test_skipped_devices_reset_on_each_resolution(
        self,
        mock_credentials: None,
    ) -> None:
        """Test that skipped_devices is reset on each call to get_resolved_inventory."""
        data_model_with_errors = {
            "mock": {
                "devices": [
                    {
                        "device_id": "device1",
                        "hostname": "",  # Invalid
                        "host": "10.1.1.1",
                        "os": "iosxe",
                    },
                ]
            }
        }

        resolver = MockDeviceResolver(data_model_with_errors)
        _ = resolver.get_resolved_inventory()

        # Should have 1 skipped device
        assert len(resolver.skipped_devices) == 1

        # Now update to valid data model
        resolver.data_model = {
            "mock": {
                "devices": [
                    {
                        "device_id": "device1",
                        "hostname": "router1",
                        "host": "10.1.1.1",
                        "os": "iosxe",
                    },
                ]
            }
        }

        _ = resolver.get_resolved_inventory()

        # Skipped devices should be reset and empty
        assert len(resolver.skipped_devices) == 0

    def test_skipped_devices_contains_device_id_and_reason(
        self,
        mock_credentials: None,
    ) -> None:
        """Test that skipped device entries have device_id and reason."""
        data_model = {
            "mock": {
                "devices": [
                    {
                        "device_id": "failed_device",
                        "hostname": "router1",
                        "host": "",  # Invalid IP will cause failure
                        "os": "iosxe",
                    },
                ]
            }
        }

        resolver = MockDeviceResolver(data_model)
        _ = resolver.get_resolved_inventory()

        assert len(resolver.skipped_devices) == 1
        skip_info = resolver.skipped_devices[0]

        assert "device_id" in skip_info
        assert skip_info["device_id"] == "failed_device"
        assert "reason" in skip_info
        assert "Invalid host IP" in skip_info["reason"]

    def test_log_message_includes_skipped_count(
        self,
        mock_credentials: None,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test that log message includes skipped count when devices are skipped."""
        data_model = {
            "mock": {
                "devices": [
                    {
                        "device_id": "device1",
                        "hostname": "router1",
                        "host": "10.1.1.1",
                        "os": "iosxe",
                    },
                    {
                        "device_id": "device2",
                        "hostname": "",  # Invalid
                        "host": "10.1.1.2",
                        "os": "nxos",
                    },
                ]
            }
        }

        with caplog.at_level("INFO"):
            resolver = MockDeviceResolver(data_model)
            _ = resolver.get_resolved_inventory()

        # Check that log includes skipped count
        assert "Resolved 1 devices for mock_arch D2D testing, skipped 1" in caplog.text
