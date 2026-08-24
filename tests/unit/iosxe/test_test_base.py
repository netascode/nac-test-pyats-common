# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for IOSXETestBase controller detection and resolution."""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from nac_test.core.types import ControllerContext

from nac_test_pyats_common.iosxe.test_base import IOSXETestBase


class TestIOSXETestBaseControllerDetection:
    """Tests for controller context detection in get_ssh_device_inventory()."""

    def test_uses_controller_context_when_available(self) -> None:
        """Uses controller_type from get_controller_context() when available."""
        # Create a controller context for SDWAN
        ctx = ControllerContext(controller_type="SDWAN", auth_method="session")

        # Mock the resolver to avoid complex setup
        mock_resolver = MagicMock()
        mock_resolver.get_resolved_inventory.return_value = [
            {"hostname": "device1", "ip": "10.0.0.1"}
        ]

        with patch(
            "nac_test_pyats_common.iosxe.test_base.get_controller_context",
            return_value=ctx,
        ):
            with patch(
                "nac_test_pyats_common.iosxe.test_base.get_resolver_for_controller",
                return_value=MagicMock(return_value=mock_resolver),
            ):
                # Data model with sdwan key
                data_model: dict[str, Any] = {"sdwan": {"devices": []}}

                # Should use SDWAN from context, not infer from data model
                result = IOSXETestBase.get_ssh_device_inventory(data_model)

                # Verify resolver was called
                assert result == [{"hostname": "device1", "ip": "10.0.0.1"}]
                assert IOSXETestBase._last_resolver == mock_resolver

    def test_falls_back_to_model_inference_on_value_error(self) -> None:
        """Falls back to data model inference when context is unavailable."""
        # Mock get_controller_context to raise ValueError
        with patch(
            "nac_test_pyats_common.iosxe.test_base.get_controller_context",
            side_effect=ValueError("no context available"),
        ):
            # Mock the resolver
            mock_resolver = MagicMock()
            mock_resolver.get_resolved_inventory.return_value = [
                {"hostname": "cc-device", "ip": "10.0.0.2"}
            ]

            with patch(
                "nac_test_pyats_common.iosxe.test_base.get_resolver_for_controller",
                return_value=MagicMock(return_value=mock_resolver),
            ):
                # Data model with catalyst_center key - should infer CC
                data_model: dict[str, Any] = {"catalyst_center": {"devices": []}}

                result = IOSXETestBase.get_ssh_device_inventory(data_model)

                # Should have inferred CC from data model
                assert result == [{"hostname": "cc-device", "ip": "10.0.0.2"}]

    def test_rejects_unsupported_controller_type(self) -> None:
        """Raises ValueError for controller types that don't support IOS-XE."""
        # Create a controller context for ACI (not supported for IOS-XE)
        ctx = ControllerContext(controller_type="ACI", auth_method="session")

        with patch(
            "nac_test_pyats_common.iosxe.test_base.get_controller_context",
            return_value=ctx,
        ):
            data_model: dict[str, Any] = {"aci": {"devices": []}}

            with pytest.raises(ValueError) as exc_info:
                IOSXETestBase.get_ssh_device_inventory(data_model)

            assert "Controller type 'ACI' does not support IOS-XE devices" in str(
                exc_info.value
            )
            # Check that all supported types are mentioned (order may vary)
            error_msg = str(exc_info.value)
            assert "SDWAN" in error_msg
            assert "CC" in error_msg
            assert "IOSXE" in error_msg

    def test_validates_data_model_has_expected_root_key(self) -> None:
        """Validates data model contains expected root key for controller type."""
        ctx = ControllerContext(controller_type="SDWAN", auth_method="session")

        # Mock resolver
        mock_resolver = MagicMock()
        mock_resolver.get_resolved_inventory.return_value = []

        with patch(
            "nac_test_pyats_common.iosxe.test_base.get_controller_context",
            return_value=ctx,
        ):
            with patch(
                "nac_test_pyats_common.iosxe.test_base.get_resolver_for_controller",
                return_value=MagicMock(return_value=mock_resolver),
            ):
                # Data model missing 'sdwan' key
                data_model: dict[str, Any] = {"catalyst_center": {"devices": []}}

                with pytest.raises(ValueError) as exc_info:
                    IOSXETestBase.get_ssh_device_inventory(data_model)

                assert "Data model missing expected root key 'sdwan'" in str(
                    exc_info.value
                )
                assert "SDWAN architecture" in str(exc_info.value)

    def test_raises_on_missing_resolver(self) -> None:
        """Raises ValueError when no resolver is registered for controller type."""
        ctx = ControllerContext(controller_type="SDWAN", auth_method="session")

        with patch(
            "nac_test_pyats_common.iosxe.test_base.get_controller_context",
            return_value=ctx,
        ):
            with patch(
                "nac_test_pyats_common.iosxe.test_base.get_resolver_for_controller",
                return_value=None,
            ):
                data_model: dict[str, Any] = {"sdwan": {"devices": []}}

                with pytest.raises(ValueError) as exc_info:
                    IOSXETestBase.get_ssh_device_inventory(data_model)

                assert (
                    "No device resolver registered for controller type 'SDWAN'"
                    in str(exc_info.value)
                )


class TestIOSXETestBaseModelInference:
    """Tests for _infer_architecture_from_data_model()."""

    def test_infers_sdwan_from_data_model(self) -> None:
        """Infers SDWAN when data model has 'sdwan' root key."""
        data_model: dict[str, Any] = {"sdwan": {"devices": []}}
        result = IOSXETestBase._infer_architecture_from_data_model(data_model)
        assert result == "SDWAN"

    def test_infers_cc_from_data_model(self) -> None:
        """Infers CC when data model has 'catalyst_center' root key."""
        data_model: dict[str, Any] = {"catalyst_center": {"devices": []}}
        result = IOSXETestBase._infer_architecture_from_data_model(data_model)
        assert result == "CC"

    def test_infers_iosxe_from_devices_key(self) -> None:
        """Infers IOSXE when data model has 'devices' root key."""
        data_model: dict[str, Any] = {"devices": [{"hostname": "router1"}]}
        result = IOSXETestBase._infer_architecture_from_data_model(data_model)
        assert result == "IOSXE"

    def test_defaults_to_iosxe_for_unknown_structure(self) -> None:
        """Defaults to IOSXE when no recognized root keys are present."""
        data_model: dict[str, Any] = {"unknown_key": {"data": []}}
        result = IOSXETestBase._infer_architecture_from_data_model(data_model)
        assert result == "IOSXE"

    def test_prefers_sdwan_over_other_keys(self) -> None:
        """Prefers SDWAN when multiple root keys are present."""
        data_model: dict[str, Any] = {
            "sdwan": {"devices": []},
            "catalyst_center": {"devices": []},
            "devices": [],
        }
        result = IOSXETestBase._infer_architecture_from_data_model(data_model)
        assert result == "SDWAN"

    def test_prefers_cc_over_devices_key(self) -> None:
        """Prefers CC over IOSXE when both keys are present."""
        data_model: dict[str, Any] = {"catalyst_center": {"devices": []}, "devices": []}
        result = IOSXETestBase._infer_architecture_from_data_model(data_model)
        assert result == "CC"


class TestIOSXETestBaseCredentials:
    """Tests for get_device_credentials()."""

    def test_returns_credentials_from_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Returns username and password from IOSXE_* env vars."""
        monkeypatch.setenv("IOSXE_USERNAME", "testuser")
        monkeypatch.setenv("IOSXE_PASSWORD", "testpass")

        test_base = IOSXETestBase()
        device = {"hostname": "router1"}

        result = test_base.get_device_credentials(device)

        assert result == {"username": "testuser", "password": "testpass"}

    def test_returns_none_when_env_vars_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Returns None values when environment variables are not set."""
        # Ensure env vars are not set (clean_controller_env fixture handles this)
        test_base = IOSXETestBase()
        device = {"hostname": "router1"}

        result = test_base.get_device_credentials(device)

        assert result == {"username": None, "password": None}
