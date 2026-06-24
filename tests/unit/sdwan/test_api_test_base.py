# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Unit tests for SDWANManagerTestBase.get_devices_from_data_model().

Tests the data model navigation logic that extracts device identifiers
(system_ip, site_id, hostname) from the NaC SD-WAN schema for use as
API query parameters.
"""


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
