# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Daniel Schmidt

"""Shared fixtures for SD-WAN unit tests."""

from typing import Any
from unittest.mock import patch

import pytest


@pytest.fixture
def make_base_instance():
    """Create a minimal SDWANManagerTestBase instance with a mocked data_model."""

    def _factory(data_model: dict[str, Any]):
        with patch(
            "nac_test_pyats_common.sdwan.api_test_base.SDWANManagerTestBase.__init__",
            return_value=None,
        ):
            from nac_test_pyats_common.sdwan.api_test_base import (
                SDWANManagerTestBase,
            )

            instance = SDWANManagerTestBase.__new__(SDWANManagerTestBase)
            instance.data_model = data_model
            return instance

    return _factory
