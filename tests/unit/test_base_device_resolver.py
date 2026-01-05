"""Unit tests for BaseDeviceResolver abstract base class.

This module tests the base device resolver functionality including:
- Inventory loading from files
- Device filtering based on test inventory
- Credential injection from environment variables
- Device dictionary building and validation
- Full resolution flow
"""

import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
import yaml

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
        # Return devices from data_model["mock"]["devices"]
        return self.data_model.get("mock", {}).get("devices", [])

    def extract_device_id(self, device_data: dict[str, Any]) -> str:
        """Extract device ID from device data."""
        return device_data["device_id"]

    def extract_hostname(self, device_data: dict[str, Any]) -> str:
        """Extract hostname from device data."""
        return device_data["hostname"]

    def extract_host_ip(self, device_data: dict[str, Any]) -> str:
        """Extract IP address from device data."""
        return device_data["host"]

    def extract_os_type(self, device_data: dict[str, Any]) -> str:
        """Extract OS type from device data."""
        return device_data["os"]

    def get_credential_env_vars(self) -> tuple[str, str]:
        """Return environment variable names for credentials."""
        return ("MOCK_USERNAME", "MOCK_PASSWORD")


@pytest.fixture
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


@pytest.fixture
def sample_test_inventory() -> dict[str, Any]:
    """Provide a sample test inventory."""
    return {
        "devices": [
            {"device_id": "device1"},
            {"device_id": "device3"},
        ]
    }


@pytest.fixture
def mock_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set mock credential environment variables."""
    monkeypatch.setenv("MOCK_USERNAME", "test_user")
    monkeypatch.setenv("MOCK_PASSWORD", "test_pass")


class TestInventoryLoading:
    """Test inventory loading functionality."""

    def test_load_inventory_from_file(
        self,
        sample_data_model: dict[str, Any],
        tmp_path: Path,
    ) -> None:
        """Test loading inventory from a YAML file."""
        # Create a test inventory file
        inventory_file = tmp_path / "test_inventory.yaml"
        inventory_data = {
            "test_inventory": {
                "devices": [
                    {"device_id": "device1"},
                    {"device_id": "device2"},
                ]
            }
        }
        inventory_file.write_text(yaml.dump(inventory_data))

        # Mock find_data_file to return our test file
        with patch("nac_test_pyats_common.common.base_device_resolver.find_data_file") as mock_find:
            mock_find.return_value = inventory_file

            resolver = MockDeviceResolver(sample_data_model)

            assert resolver.test_inventory == inventory_data["test_inventory"]
            assert len(resolver.test_inventory["devices"]) == 2

    def test_empty_inventory_when_file_not_found(
        self,
        sample_data_model: dict[str, Any],
    ) -> None:
        """Test that empty inventory is used when file is not found."""
        with patch("nac_test_pyats_common.common.base_device_resolver.find_data_file") as mock_find:
            mock_find.return_value = None

            resolver = MockDeviceResolver(sample_data_model)

            assert resolver.test_inventory == {}

    def test_nested_inventory_format(
        self,
        sample_data_model: dict[str, Any],
        tmp_path: Path,
    ) -> None:
        """Test loading inventory with nested format: {arch: {test_inventory: {...}}}."""
        inventory_file = tmp_path / "test_inventory.yaml"
        inventory_data = {
            "mock": {
                "test_inventory": {
                    "devices": [
                        {"device_id": "device1"},
                    ]
                }
            }
        }
        inventory_file.write_text(yaml.dump(inventory_data))

        with patch("nac_test_pyats_common.common.base_device_resolver.find_data_file") as mock_find:
            mock_find.return_value = inventory_file

            resolver = MockDeviceResolver(sample_data_model)

            assert resolver.test_inventory == inventory_data["mock"]["test_inventory"]
            assert len(resolver.test_inventory["devices"]) == 1

    def test_flat_inventory_format(
        self,
        sample_data_model: dict[str, Any],
        tmp_path: Path,
    ) -> None:
        """Test loading inventory with flat format: {test_inventory: {...}}."""
        inventory_file = tmp_path / "test_inventory.yaml"
        inventory_data = {
            "test_inventory": {
                "devices": [
                    {"device_id": "device2"},
                ]
            }
        }
        inventory_file.write_text(yaml.dump(inventory_data))

        with patch("nac_test_pyats_common.common.base_device_resolver.find_data_file") as mock_find:
            mock_find.return_value = inventory_file

            resolver = MockDeviceResolver(sample_data_model)

            assert resolver.test_inventory == inventory_data["test_inventory"]
            assert len(resolver.test_inventory["devices"]) == 1

    def test_yaml_error_returns_empty_inventory(
        self,
        sample_data_model: dict[str, Any],
        tmp_path: Path,
    ) -> None:
        """Test that YAML parsing errors result in empty inventory."""
        inventory_file = tmp_path / "test_inventory.yaml"
        inventory_file.write_text("invalid: yaml: content: [")

        with patch("nac_test_pyats_common.common.base_device_resolver.find_data_file") as mock_find:
            mock_find.return_value = inventory_file

            resolver = MockDeviceResolver(sample_data_model)

            assert resolver.test_inventory == {}

    def test_os_error_returns_empty_inventory(
        self,
        sample_data_model: dict[str, Any],
    ) -> None:
        """Test that OS errors when reading file result in empty inventory."""
        with patch("nac_test_pyats_common.common.base_device_resolver.find_data_file") as mock_find:
            mock_find.return_value = Path("/nonexistent/path/file.yaml")

            resolver = MockDeviceResolver(sample_data_model)

            assert resolver.test_inventory == {}


class TestDeviceFiltering:
    """Test device filtering based on test inventory."""

    def test_all_devices_returned_when_no_test_inventory_specified(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test that all devices are returned when test_inventory has no devices."""
        resolver = MockDeviceResolver(sample_data_model, test_inventory={})
        devices = resolver.get_resolved_inventory()

        assert len(devices) == 3
        device_ids = [d["device_id"] for d in devices]
        assert "device1" in device_ids
        assert "device2" in device_ids
        assert "device3" in device_ids

    def test_filtering_to_only_test_inventory_devices(
        self,
        sample_data_model: dict[str, Any],
        sample_test_inventory: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test filtering devices to only those in test_inventory."""
        resolver = MockDeviceResolver(sample_data_model, test_inventory=sample_test_inventory)
        devices = resolver.get_resolved_inventory()

        assert len(devices) == 2
        device_ids = [d["device_id"] for d in devices]
        assert "device1" in device_ids
        assert "device3" in device_ids
        assert "device2" not in device_ids

    def test_warning_when_test_inventory_device_not_found(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test warning is logged when test_inventory device not in data model."""
        test_inventory = {
            "devices": [
                {"device_id": "device1"},
                {"device_id": "nonexistent_device"},
            ]
        }

        resolver = MockDeviceResolver(sample_data_model, test_inventory=test_inventory)
        devices = resolver.get_resolved_inventory()

        assert len(devices) == 1
        assert devices[0]["device_id"] == "device1"
        assert "nonexistent_device" in caplog.text
        assert "not found in mock_arch data model" in caplog.text

    def test_device_id_lookup_from_various_inventory_fields(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test device ID can be extracted from various inventory field names."""
        test_inventory = {
            "devices": [
                {"chassis_id": "device1"},  # Using chassis_id
                {"node_id": "device2"},      # Using node_id
                {"hostname": "device3"},     # Using hostname
            ]
        }

        resolver = MockDeviceResolver(sample_data_model, test_inventory=test_inventory)
        devices = resolver.get_resolved_inventory()

        # All devices should be found using different field names
        assert len(devices) == 3
        device_ids = [d["device_id"] for d in devices]
        assert "device1" in device_ids
        assert "device2" in device_ids
        assert "device3" in device_ids


class TestCredentialInjection:
    """Test credential injection from environment variables."""

    def test_successful_credential_injection(
        self,
        sample_data_model: dict[str, Any],
        sample_test_inventory: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test successful injection of credentials from environment variables."""
        resolver = MockDeviceResolver(sample_data_model, test_inventory=sample_test_inventory)
        devices = resolver.get_resolved_inventory()

        for device in devices:
            assert device["username"] == "test_user"
            assert device["password"] == "test_pass"

    def test_error_when_username_env_var_missing(
        self,
        sample_data_model: dict[str, Any],
        sample_test_inventory: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test ValueError raised when username environment variable is missing."""
        monkeypatch.setenv("MOCK_PASSWORD", "test_pass")
        # MOCK_USERNAME is not set

        resolver = MockDeviceResolver(sample_data_model, test_inventory=sample_test_inventory)

        with pytest.raises(ValueError) as exc_info:
            resolver.get_resolved_inventory()

        assert "MOCK_USERNAME" in str(exc_info.value)
        assert "Missing required credential environment variables" in str(exc_info.value)

    def test_error_when_password_env_var_missing(
        self,
        sample_data_model: dict[str, Any],
        sample_test_inventory: dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test ValueError raised when password environment variable is missing."""
        monkeypatch.setenv("MOCK_USERNAME", "test_user")
        # MOCK_PASSWORD is not set

        resolver = MockDeviceResolver(sample_data_model, test_inventory=sample_test_inventory)

        with pytest.raises(ValueError) as exc_info:
            resolver.get_resolved_inventory()

        assert "MOCK_PASSWORD" in str(exc_info.value)
        assert "Missing required credential environment variables" in str(exc_info.value)

    def test_error_message_includes_architecture_name(
        self,
        sample_data_model: dict[str, Any],
        sample_test_inventory: dict[str, Any],
    ) -> None:
        """Test that credential error message includes the architecture name."""
        # No credentials set
        resolver = MockDeviceResolver(sample_data_model, test_inventory=sample_test_inventory)

        with pytest.raises(ValueError) as exc_info:
            resolver.get_resolved_inventory()

        assert "mock_arch D2D testing" in str(exc_info.value)

    def test_both_credentials_missing_lists_both(
        self,
        sample_data_model: dict[str, Any],
        sample_test_inventory: dict[str, Any],
    ) -> None:
        """Test that both missing credentials are listed in error message."""
        # No credentials set
        resolver = MockDeviceResolver(sample_data_model, test_inventory=sample_test_inventory)

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
        resolver = MockDeviceResolver(sample_data_model, test_inventory={})
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
        resolver = MockDeviceResolver(sample_data_model, test_inventory={})
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
        resolver = MockDeviceResolver(sample_data_model, test_inventory={})
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
        resolver = MockDeviceResolver(sample_data_model, test_inventory={})
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
        resolver = MockDeviceResolver(sample_data_model, test_inventory={})
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
        resolver = MockDeviceResolver(sample_data_model, test_inventory={})

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
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test that devices with invalid data are skipped with warning."""
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

        resolver = MockDeviceResolver(data_model, test_inventory={})
        devices = resolver.get_resolved_inventory()

        # Should only get 2 valid devices
        assert len(devices) == 2
        device_ids = [d["device_id"] for d in devices]
        assert "device1" in device_ids
        assert "device3" in device_ids
        assert "device2" not in device_ids

        # Check for warning in logs
        assert "Skipping device device2" in caplog.text


class TestFullResolutionFlow:
    """Test the complete device resolution flow."""

    def test_get_resolved_inventory_returns_properly_formatted_devices(
        self,
        sample_data_model: dict[str, Any],
        sample_test_inventory: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test that get_resolved_inventory returns properly formatted devices."""
        resolver = MockDeviceResolver(sample_data_model, test_inventory=sample_test_inventory)
        devices = resolver.get_resolved_inventory()

        assert len(devices) == 2

        # Check first device
        device1 = next(d for d in devices if d["device_id"] == "device1")
        assert device1["hostname"] == "router1"
        assert device1["host"] == "10.1.1.1"
        assert device1["os"] == "iosxe"
        assert device1["username"] == "test_user"
        assert device1["password"] == "test_pass"
        assert device1["device_id"] == "device1"

        # Check second device
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
        resolver = MockDeviceResolver(sample_data_model, test_inventory={})
        devices = resolver.get_resolved_inventory()

        required_fields = ["hostname", "host", "os", "username", "password", "device_id"]

        for device in devices:
            for field in required_fields:
                assert field in device
                assert device[field] is not None
                assert device[field] != ""

    def test_merges_inventory_data_with_device_data(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test that test inventory data is merged with device data."""
        test_inventory = {
            "devices": [
                {
                    "device_id": "device1",
                    "custom_field": "custom_value",
                    "tags": ["production", "edge"],
                }
            ]
        }

        # Create a custom resolver that preserves extra fields from device_data
        class MergingResolver(MockDeviceResolver):
            def build_device_dict(self, device_data: dict[str, Any]) -> dict[str, Any]:
                # Get the standard fields from parent
                device_dict = super().build_device_dict(device_data)

                # Add any extra fields from test inventory that were merged
                if "custom_field" in device_data:
                    device_dict["custom_field"] = device_data["custom_field"]
                if "tags" in device_data:
                    device_dict["tags"] = device_data["tags"]

                return device_dict

        resolver = MergingResolver(sample_data_model, test_inventory=test_inventory)
        devices = resolver.get_resolved_inventory()

        assert len(devices) == 1
        device = devices[0]

        # Standard fields from data model
        assert device["hostname"] == "router1"
        assert device["host"] == "10.1.1.1"

        # Custom fields from test inventory
        assert device["custom_field"] == "custom_value"
        assert device["tags"] == ["production", "edge"]

    def test_preserves_connection_options_from_test_inventory(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test that connection_options from test_inventory is preserved in device dict.

        This is critical for SSH port customization in D2D testing.
        The testbed generator reads connection_options to set custom SSH ports.
        """
        test_inventory = {
            "devices": [
                {
                    "device_id": "device1",
                    "connection_options": {
                        "protocol": "ssh",
                        "port": 4322,
                    }
                }
            ]
        }

        resolver = MockDeviceResolver(sample_data_model, test_inventory=test_inventory)
        devices = resolver.get_resolved_inventory()

        assert len(devices) == 1
        device = devices[0]

        # Standard fields from data model
        assert device["hostname"] == "router1"
        assert device["host"] == "10.1.1.1"
        assert device["os"] == "iosxe"

        # connection_options must be preserved from test_inventory
        assert "connection_options" in device
        assert device["connection_options"]["protocol"] == "ssh"
        assert device["connection_options"]["port"] == 4322

    def test_logging_output(
        self,
        sample_data_model: dict[str, Any],
        sample_test_inventory: dict[str, Any],
        mock_credentials: None,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Test that appropriate logging is produced during resolution."""
        with caplog.at_level("INFO"):
            resolver = MockDeviceResolver(sample_data_model, test_inventory=sample_test_inventory)
            devices = resolver.get_resolved_inventory()

        # Check for key log messages
        assert "Resolving device inventory for mock_arch" in caplog.text
        assert "Resolved 2 devices for mock_arch D2D testing" in caplog.text


class TestAbstractMethods:
    """Test that abstract methods are properly enforced."""

    def test_cannot_instantiate_base_class(self) -> None:
        """Test that BaseDeviceResolver cannot be instantiated directly."""
        with pytest.raises(TypeError) as exc_info:
            BaseDeviceResolver({})

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
            IncompleteResolver({})

        assert "Can't instantiate abstract class" in str(exc_info.value)


class TestOptionalOverrides:
    """Test optional method overrides."""

    def test_custom_inventory_filename(
        self,
        sample_data_model: dict[str, Any],
        tmp_path: Path,
    ) -> None:
        """Test overriding get_inventory_filename to use custom filename."""

        class CustomResolver(MockDeviceResolver):
            def get_inventory_filename(self) -> str:
                return "custom_inventory.yaml"

        # Create custom inventory file
        inventory_file = tmp_path / "custom_inventory.yaml"
        inventory_data = {
            "test_inventory": {
                "devices": [{"device_id": "custom_device"}]
            }
        }
        inventory_file.write_text(yaml.dump(inventory_data))

        with patch("nac_test_pyats_common.common.base_device_resolver.find_data_file") as mock_find:
            def find_side_effect(filename: str) -> Path | None:
                if filename == "custom_inventory.yaml":
                    return inventory_file
                return None

            mock_find.side_effect = find_side_effect

            resolver = CustomResolver(sample_data_model)

            assert len(resolver.test_inventory["devices"]) == 1
            assert resolver.test_inventory["devices"][0]["device_id"] == "custom_device"

    def test_custom_build_device_dict(
        self,
        sample_data_model: dict[str, Any],
        mock_credentials: None,
    ) -> None:
        """Test overriding build_device_dict to add custom fields."""

        class CustomResolver(MockDeviceResolver):
            def build_device_dict(self, device_data: dict[str, Any]) -> dict[str, Any]:
                # Call parent implementation
                device_dict = super().build_device_dict(device_data)

                # Add custom fields
                device_dict["custom_field"] = "custom_value"
                device_dict["site_id"] = device_data.get("site_id", "unknown")

                return device_dict

        resolver = CustomResolver(sample_data_model, test_inventory={})
        devices = resolver.get_resolved_inventory()

        for device in devices:
            assert device["custom_field"] == "custom_value"
            assert "site_id" in device


class TestErrorHandling:
    """Test error handling in various scenarios."""

    def test_handles_missing_device_fields_gracefully(
        self,
        mock_credentials: None,
        caplog: pytest.LogCaptureFixture,
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

        resolver = ErrorResolver(data_model, test_inventory={})
        devices = resolver.get_resolved_inventory()

        # Should only get device1, device2 should be skipped
        assert len(devices) == 1
        assert devices[0]["device_id"] == "device1"

        # Check for warning about device2
        assert "Skipping device device2" in caplog.text

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

        resolver = ErrorResolver(sample_data_model, test_inventory={})

        # Should return "<unknown>" for error case
        result = resolver._safe_extract_device_id({"error": True})
        assert result == "<unknown>"

        # Should return actual ID for valid case
        result = resolver._safe_extract_device_id({"device_id": "test123"})
        assert result == "test123"