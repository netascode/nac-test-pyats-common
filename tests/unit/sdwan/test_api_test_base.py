# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for SDWANManagerTestBase.

Tests cover:
- Header construction in get_sdwan_manager_client() (token auth, session auth)
- Data model navigation in get_devices_from_data_model()
"""

from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from nac_test_pyats_common.sdwan.api_test_base import SDWANManagerTestBase


@pytest.fixture
def test_base(mocker: MockerFixture) -> SDWANManagerTestBase:
    """Create a SDWANManagerTestBase instance with mocked internals."""
    instance = SDWANManagerTestBase.__new__(SDWANManagerTestBase)
    instance.controller_url = "https://sdwan.example.com"

    # Mock pool.get_client to capture the headers passed to it
    mock_pool = MagicMock()
    mock_pool.get_client.return_value = MagicMock()
    instance.pool = mock_pool

    # Mock wrap_client_for_tracking to return the base client unchanged
    instance.wrap_client_for_tracking = MagicMock(  # type: ignore[assignment]
        side_effect=lambda client, **kw: client,
    )

    return instance


class TestGetSDWANManagerClientHeaders:
    """Test header construction in get_sdwan_manager_client()."""

    def test_token_auth_headers(self, test_base: SDWANManagerTestBase) -> None:
        """Token auth sets Bearer Authorization and X-XSRF-TOKEN from JWT."""
        test_base.auth_data = {
            "auth_method": "token",
            "api_token": "my-jwt-token",
            "csrf_token": "csrf-from-jwt",
        }

        test_base.get_sdwan_manager_client()

        headers = test_base.pool.get_client.call_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer my-jwt-token"
        assert headers["X-XSRF-TOKEN"] == "csrf-from-jwt"
        assert headers["Content-Type"] == "application/json"
        assert "Cookie" not in headers

    def test_session_auth_headers_with_xsrf(
        self, test_base: SDWANManagerTestBase
    ) -> None:
        """Session auth sets JSESSIONID cookie and X-XSRF-TOKEN."""
        test_base.auth_data = {
            "auth_method": "session",
            "jsessionid": "sess-abc123",
            "xsrf_token": "xsrf-def456",
        }

        test_base.get_sdwan_manager_client()

        headers = test_base.pool.get_client.call_args.kwargs["headers"]
        assert headers["Cookie"] == "JSESSIONID=sess-abc123"
        assert headers["X-XSRF-TOKEN"] == "xsrf-def456"
        assert headers["Content-Type"] == "application/json"
        assert "Authorization" not in headers

    def test_session_auth_headers_without_xsrf(
        self, test_base: SDWANManagerTestBase
    ) -> None:
        """Pre-19.2 session auth: JSESSIONID cookie only, no X-XSRF-TOKEN."""
        test_base.auth_data = {
            "auth_method": "session",
            "jsessionid": "sess-old",
            "xsrf_token": None,
        }

        test_base.get_sdwan_manager_client()

        headers = test_base.pool.get_client.call_args.kwargs["headers"]
        assert headers["Cookie"] == "JSESSIONID=sess-old"
        assert "X-XSRF-TOKEN" not in headers

    def test_unsupported_auth_method_raises(
        self, test_base: SDWANManagerTestBase
    ) -> None:
        """Unknown auth_method raises ValueError."""
        test_base.auth_data = {"auth_method": "kerberos"}

        with pytest.raises(ValueError, match="Unsupported auth_method"):
            test_base.get_sdwan_manager_client()


class TestGetDevicesFromDataModel:
    """Tests for get_devices_from_data_model method."""

    def test_extracts_devices_from_single_site(self, make_base_instance):
        """Extracts devices from a single site with routers."""
        data_model = {
            "sdwan": {
                "sites": [
                    {
                        "id": 100,
                        "routers": [
                            {
                                "device_variables": {
                                    "system_ip": "10.0.0.1",
                                    "site_id": 100,
                                    "host_name": "dc-edge-01",
                                },
                            },
                        ],
                    },
                ],
            },
        }
        instance = make_base_instance(data_model)
        devices = instance.get_devices_from_data_model()

        assert len(devices) == 1
        assert devices[0]["system_ip"] == "10.0.0.1"
        assert devices[0]["site_id"] == 100
        assert devices[0]["hostname"] == "dc-edge-01"

    def test_extracts_devices_from_multiple_sites(self, make_base_instance):
        """Extracts devices across multiple sites."""
        data_model = {
            "sdwan": {
                "sites": [
                    {
                        "id": 100,
                        "routers": [
                            {
                                "device_variables": {
                                    "system_ip": "10.0.0.1",
                                    "site_id": 100,
                                    "host_name": "dc-edge-01",
                                },
                            },
                        ],
                    },
                    {
                        "id": 200,
                        "routers": [
                            {
                                "device_variables": {
                                    "system_ip": "10.0.0.3",
                                    "site_id": 200,
                                    "host_name": "br-edge-01",
                                },
                            },
                            {
                                "device_variables": {
                                    "system_ip": "10.0.0.4",
                                    "site_id": 200,
                                    "host_name": "br-edge-02",
                                },
                            },
                        ],
                    },
                ],
            },
        }
        instance = make_base_instance(data_model)
        devices = instance.get_devices_from_data_model()

        assert len(devices) == 3
        assert devices[0]["system_ip"] == "10.0.0.1"
        assert devices[1]["system_ip"] == "10.0.0.3"
        assert devices[2]["system_ip"] == "10.0.0.4"

    def test_uses_system_hostname_for_ux1(self, make_base_instance):
        """Falls back to system_hostname (UX 1.0) when host_name not present."""
        data_model = {
            "sdwan": {
                "sites": [
                    {
                        "id": 300,
                        "routers": [
                            {
                                "device_variables": {
                                    "system_ip": "10.0.0.5",
                                    "site_id": 300,
                                    "system_hostname": "SD-BR02-C8KV-R1",
                                },
                            },
                        ],
                    },
                ],
            },
        }
        instance = make_base_instance(data_model)
        devices = instance.get_devices_from_data_model()

        assert devices[0]["hostname"] == "SD-BR02-C8KV-R1"

    def test_falls_back_to_system_ip_for_hostname(self, make_base_instance):
        """Uses system_ip when no host_name or system_hostname exists."""
        data_model = {
            "sdwan": {
                "sites": [
                    {
                        "id": 100,
                        "routers": [
                            {
                                "device_variables": {
                                    "system_ip": "10.0.0.1",
                                    "site_id": 100,
                                },
                            },
                        ],
                    },
                ],
            },
        }
        instance = make_base_instance(data_model)
        devices = instance.get_devices_from_data_model()

        assert devices[0]["hostname"] == "10.0.0.1"

    def test_uses_site_id_from_site_level(self, make_base_instance):
        """Falls back to site-level id when device_variables has no site_id."""
        data_model = {
            "sdwan": {
                "sites": [
                    {
                        "id": 100,
                        "routers": [
                            {
                                "device_variables": {
                                    "system_ip": "10.0.0.1",
                                    "host_name": "router1",
                                },
                            },
                        ],
                    },
                ],
            },
        }
        instance = make_base_instance(data_model)
        devices = instance.get_devices_from_data_model()

        assert devices[0]["site_id"] == 100

    def test_skips_routers_without_system_ip(self, make_base_instance):
        """Routers missing system_ip are excluded from results."""
        data_model = {
            "sdwan": {
                "sites": [
                    {
                        "id": 100,
                        "routers": [
                            {
                                "device_variables": {
                                    "system_ip": "10.0.0.1",
                                    "host_name": "router1",
                                },
                            },
                            {
                                "device_variables": {
                                    "host_name": "router-no-ip",
                                },
                            },
                        ],
                    },
                ],
            },
        }
        instance = make_base_instance(data_model)
        devices = instance.get_devices_from_data_model()

        assert len(devices) == 1
        assert devices[0]["hostname"] == "router1"

    def test_returns_empty_list_for_no_sites(self, make_base_instance):
        """Returns empty list when no sites are defined."""
        data_model = {"sdwan": {"sites": []}}
        instance = make_base_instance(data_model)
        devices = instance.get_devices_from_data_model()

        assert devices == []

    def test_returns_empty_list_for_empty_data_model(self, make_base_instance):
        """Returns empty list when data model has no sdwan key."""
        data_model = {}
        instance = make_base_instance(data_model)
        devices = instance.get_devices_from_data_model()

        assert devices == []

    def test_handles_site_with_no_routers(self, make_base_instance):
        """Gracefully handles sites that have no routers key."""
        data_model = {
            "sdwan": {
                "sites": [
                    {"id": 100},
                ],
            },
        }
        instance = make_base_instance(data_model)
        devices = instance.get_devices_from_data_model()

        assert devices == []

    def test_host_name_takes_priority_over_system_hostname(self, make_base_instance):
        """host_name (UX 2.0) is preferred over system_hostname (UX 1.0)."""
        data_model = {
            "sdwan": {
                "sites": [
                    {
                        "id": 100,
                        "routers": [
                            {
                                "device_variables": {
                                    "system_ip": "10.0.0.1",
                                    "host_name": "ux2-name",
                                    "system_hostname": "ux1-name",
                                },
                            },
                        ],
                    },
                ],
            },
        }
        instance = make_base_instance(data_model)
        devices = instance.get_devices_from_data_model()

        assert devices[0]["hostname"] == "ux2-name"
