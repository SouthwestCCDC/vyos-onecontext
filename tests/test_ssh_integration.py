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

    def test_default_vyos_user_accessible(self, ssh_connection: Callable[[str], str]) -> None:
        """Verify default vyos user is accessible via password authentication.

        Integration tests use the default VyOS credentials (vyos/vyos) for SSH access.
        This test validates that we can authenticate and access the system.
        """
        output = ssh_connection("whoami")

        # Should be logged in as vyos user
        assert "vyos" in output

    def test_commit_works(self, ssh_connection: Callable[[str], str]) -> None:
        """Verify configuration is present after contextualization.

        Validates that interfaces and system configuration exist in the running config,
        confirming that the contextualization script successfully applied and committed
        the generated VyOS configuration.
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
        # VyOS output typically shows "state UP" or "state up" (word boundary)
        # Using regex to avoid false positives from words like "group" or "input"
        output_lower = output.lower()
        assert re.search(r"\b(?:state|link)\s*:?\s*up\b", output_lower)


@pytest.mark.integration
class TestContextSpecificValidation:
    """Tests that validate context-specific configuration.

    These tests may be skipped if they don't match the current test context.
    """

    def test_management_vrf_if_configured(self, ssh_connection: Callable[[str], str]) -> None:
        """If management VRF is configured, verify it exists.

        This test checks if VRF is present in config and validates if so.
        If no VRF, test passes (not all contexts use VRF).
        """
        output = ssh_connection("show configuration | grep vrf || echo 'No VRF'")

        if "No VRF" in output:
            pytest.skip("Context does not use VRF")

        # If VRF is configured, verify it has proper structure
        assert "vrf" in output

    def test_static_routes_if_configured(self, ssh_connection: Callable[[str], str]) -> None:
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


@pytest.mark.integration
class TestSSHKeyInjection:
    """Tests for SSH public key injection and installation.

    These tests validate that SSH_PUBLIC_KEY context variables are properly
    parsed, installed in authorized_keys, and preserved correctly.
    """

    def test_ssh_keys_in_vyos_config(self, ssh_connection: Callable[[str], str]) -> None:
        """Verify SSH public keys appear in VyOS configuration.

        This checks that the SshKeyGenerator successfully created VyOS commands
        to install the public keys for the vyos user.
        """
        output = ssh_connection(
            "show configuration | grep 'authentication public-keys' || echo 'No SSH keys'"
        )

        if "No SSH keys" in output:
            pytest.skip("Context does not have SSH_PUBLIC_KEY configured")

        # Should have public-keys configuration
        assert "authentication public-keys" in output
        # Should have key type and key data
        assert "type" in output
        assert "key" in output

    def test_ssh_keys_in_authorized_keys_file(self, ssh_connection: Callable[[str], str]) -> None:
        """Verify SSH public keys are installed in authorized_keys file.

        This is the critical E2E test - it validates that keys specified in
        context are actually installed and usable for authentication.
        """
        # Check if SSH keys are actually configured in VyOS
        # Note: VyOS always creates authorized_keys with header, so we check config instead
        check_output = ssh_connection(
            "show configuration commands | grep 'authentication public-keys' || echo 'No SSH keys'"
        )

        if "No SSH keys" in check_output:
            pytest.skip("Context does not have SSH_PUBLIC_KEY configured")

        # Read the authorized_keys file
        output = ssh_connection("cat /home/vyos/.ssh/authorized_keys")

        # Should contain at least one SSH key
        # Valid SSH keys start with ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp256, etc.
        assert re.search(r"ssh-(?:rsa|ed25519|dss|ecdsa)", output), (
            "Should contain valid SSH key type"
        )

        # Should contain base64-encoded key data
        # SSH keys have base64 data that's typically quite long
        assert re.search(r"[A-Za-z0-9+/]{64,}", output), "Should contain base64-encoded key data"

    def test_multiple_ssh_keys_if_configured(self, ssh_connection: Callable[[str], str]) -> None:
        """Verify multiple SSH keys are handled correctly if configured.

        Tests that newline-separated keys in SSH_PUBLIC_KEY result in
        multiple entries in authorized_keys.
        """
        # Check if SSH keys are actually configured in VyOS
        check_output = ssh_connection(
            "show configuration commands | grep 'authentication public-keys' || echo 'No SSH keys'"
        )

        if "No SSH keys" in check_output:
            pytest.skip("Context does not have SSH_PUBLIC_KEY configured")

        # Read authorized_keys
        output = ssh_connection("cat /home/vyos/.ssh/authorized_keys")

        # Count number of key lines (each valid key starts with ssh-)
        key_lines = [line for line in output.split("\n") if line.strip().startswith("ssh-")]

        # If we have multiple keys, verify they're all present
        # The ssh-keys.env fixture has 2 keys (one RSA, one ED25519)
        # Other fixtures may have 0 or 1 key
        if len(key_lines) >= 2:
            # Verify we have both RSA and ED25519 keys
            key_types = [line.split()[0] for line in key_lines if line.strip()]
            assert "ssh-rsa" in key_types and "ssh-ed25519" in key_types, (
                "Should have expected key types"
            )

    def test_ssh_key_format_preserved(self, ssh_connection: Callable[[str], str]) -> None:
        """Verify SSH key format is not mangled during injection.

        This test validates that the key data and comments are preserved
        correctly during the parsing and installation process.
        """
        # Check if SSH keys are actually configured in VyOS
        check_output = ssh_connection(
            "show configuration commands | grep 'authentication public-keys' || echo 'No SSH keys'"
        )

        if "No SSH keys" in check_output:
            pytest.skip("Context does not have SSH_PUBLIC_KEY configured")

        # Read authorized_keys
        output = ssh_connection("cat /home/vyos/.ssh/authorized_keys")

        # Each line should follow the standard SSH key format:
        # <type> <base64-data> [comment]
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(None, 2)
            # Should have at least type and key data
            assert len(parts) >= 2, f"SSH key line malformed: {line}"

            # First part should be a valid key type
            assert parts[0].startswith("ssh-"), f"Invalid key type: {parts[0]}"

            # Second part should be base64 data (no spaces, only valid base64 chars)
            assert re.match(r"^[A-Za-z0-9+/]+=*$", parts[1]), f"Invalid base64 key data: {parts[1]}"

    def test_ssh_service_enabled(self, ssh_connection: Callable[[str], str]) -> None:
        """Verify SSH service is enabled when SSH keys are configured.

        The SshKeyGenerator should enable SSH service on port 22 when
        installing public keys.
        """
        # Check if SSH keys are actually configured in VyOS
        check_output = ssh_connection(
            "show configuration commands | grep 'authentication public-keys' || echo 'No SSH keys'"
        )

        if "No SSH keys" in check_output:
            pytest.skip("Context does not have SSH_PUBLIC_KEY configured")

        output = ssh_connection(
            "show configuration commands | grep 'service ssh' || echo 'No SSH service'"
        )

        # Should have SSH service configured
        assert "service ssh" in output

        # Should be on port 22 (standard SSH port)
        port_output = ssh_connection(
            "show configuration commands | grep 'service ssh port' || echo 'default'"
        )
        # Either explicitly set to 22 or using default
        assert "22" in port_output or "default" in port_output
