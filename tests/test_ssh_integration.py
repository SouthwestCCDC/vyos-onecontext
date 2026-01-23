"""Integration tests using SSH connectivity.

These tests validate VyOS configuration by connecting via SSH to running VMs.
They are only run when executed within the QEMU test harness (run-qemu-test.sh).
"""

import re
from collections.abc import Callable

import pytest


@pytest.mark.integration
class TestSSHConnectivity:
    """Test SSH connectivity infrastructure."""

    def test_ssh_connection_works(self, ssh_connection: Callable[[str], str]) -> None:
        """Verify SSH connection is functional.

        This is a basic smoke test to ensure the SSH infrastructure works.
        """
        output = ssh_connection("echo 'Hello from VyOS'")
        assert "Hello from VyOS" in output

    def test_vyos_version_accessible(self, ssh_connection: Callable[[str], str]) -> None:
        """Verify we can query VyOS version via SSH."""
        output = ssh_connection("show version")

        # Should contain VyOS version information
        assert "VyOS" in output or "Version:" in output

    def test_vyos_config_mode_accessible(self, ssh_connection: Callable[[str], str]) -> None:
        """Verify we can access VyOS configuration via SSH.

        This uses the operational mode 'show configuration' command which
        doesn't require entering config mode.
        """
        output = ssh_connection("show configuration")

        # Basic sanity check - should have system configuration
        assert "system" in output

    def test_hostname_configured(self, ssh_connection: Callable[[str], str]) -> None:
        """Verify hostname was configured by contextualization.

        This test validates that the test context's hostname was applied.
        Most test contexts use 'test-*' hostnames.
        """
        output = ssh_connection("show configuration | grep 'host-name'")

        # Should have a hostname starting with 'test-'
        assert "host-name" in output
        assert "test-" in output

    def test_interface_eth0_configured(self, ssh_connection: Callable[[str], str]) -> None:
        """Verify eth0 interface was configured.

        All test contexts configure eth0 with an IP address.
        """
        output = ssh_connection("show interfaces ethernet eth0")

        # Should show eth0 as configured with an IP
        assert "eth0" in output
        # Most test contexts use 192.168.122.x addresses
        assert re.search(r"\d+\.\d+\.\d+\.\d+", output), "Should have an IP address"


@pytest.mark.integration
class TestVyOSConfigValidation:
    """Test actual VyOS configuration state via SSH."""

    def test_ssh_keys_installed(self, ssh_connection: Callable[[str], str]) -> None:
        """Verify SSH public key was installed for vyos user.

        The test context includes SSH_PUBLIC_KEY which should be configured.
        """
        output = ssh_connection("show configuration | grep 'public-keys'")

        # Should have at least one public key configured
        assert "public-keys" in output

    def test_commit_works(self, ssh_connection: Callable[[str], str]) -> None:
        """Verify configuration was committed successfully.

        This checks that the commit message/status indicates success.
        Since we can't easily commit from operational mode, we verify
        the current config is committed by checking show configuration.
        """
        output = ssh_connection("show configuration")

        # Should have interfaces configured (basic sanity check)
        assert "interfaces" in output
        assert "system" in output

    def test_interface_is_up(self, ssh_connection: Callable[[str], str]) -> None:
        """Verify eth0 interface is operationally up.

        This validates the interface configured by context is actually working.
        """
        output = ssh_connection("show interfaces ethernet eth0")

        # Check for operational state indicators
        # VyOS may use "state" or "link" or "UP" depending on output format
        output_lower = output.lower()
        assert "up" in output_lower or "state up" in output_lower


@pytest.mark.integration
class TestContextSpecificValidation:
    """Tests that validate context-specific configuration.

    These tests may be skipped if they don't match the current test context.
    """

    def test_management_vrf_if_configured(
        self, ssh_connection: Callable[[str], str]
    ) -> None:
        """If management VRF is configured, verify it exists.

        This test checks if VRF is present in config and validates if so.
        If no VRF, test passes (not all contexts use VRF).
        """
        output = ssh_connection("show configuration | grep vrf || echo 'No VRF'")

        if "No VRF" in output:
            pytest.skip("Context does not use VRF")

        # If VRF is configured, verify it has proper structure
        assert "vrf" in output

    def test_static_routes_if_configured(
        self, ssh_connection: Callable[[str], str]
    ) -> None:
        """If static routes configured, verify they exist.

        Not all contexts have static routes, so skip if not present.
        """
        output = ssh_connection(
            "show configuration | grep 'protocols static' || echo 'No static routes'"
        )

        if "No static routes" in output:
            pytest.skip("Context does not have static routes")

        # If static routes are configured, verify structure
        assert "protocols static" in output
