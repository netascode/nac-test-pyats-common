"""Unit tests for IOS-XE device resolver registry."""

from collections.abc import Generator

import pytest

from nac_test_pyats_common.common import BaseDeviceResolver
from nac_test_pyats_common.iosxe import registry


@pytest.fixture(autouse=True)
def clean_registry() -> Generator[None, None, None]:
    """Clean the registry before and after each test to ensure isolation."""
    # Store original state
    original = registry._IOSXE_RESOLVER_REGISTRY.copy()

    # Clear registry before test
    registry._IOSXE_RESOLVER_REGISTRY.clear()

    yield

    # Restore original state after test
    registry._IOSXE_RESOLVER_REGISTRY.clear()
    registry._IOSXE_RESOLVER_REGISTRY.update(original)


def test_duplicate_registration_raises_valueerror() -> None:
    """Test that registering the same controller type twice raises ValueError."""

    # Create a mock resolver class
    @registry.register_iosxe_resolver("TEST_CONTROLLER")
    class TestResolver1(BaseDeviceResolver):
        pass

    # Attempt to register another resolver for the same controller type
    with pytest.raises(ValueError) as exc_info:

        @registry.register_iosxe_resolver("TEST_CONTROLLER")
        class TestResolver2(BaseDeviceResolver):
            pass

    # Verify the error message is helpful
    error_msg = str(exc_info.value)
    assert "TEST_CONTROLLER" in error_msg
    assert "already registered" in error_msg
    assert "TestResolver1" in error_msg
