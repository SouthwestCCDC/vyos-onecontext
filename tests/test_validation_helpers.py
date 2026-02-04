"""Unit tests for validation helpers with mocked SSH responses.

These tests validate the validation helper functions using mocked SSH
command outputs. This allows testing the parsing and validation logic
without requiring a live VyOS instance.
"""

from unittest.mock import Mock

from tests.validation_helpers import (
    ValidationResult,
    check_default_route,
    check_dnat_rule,
    check_hostname,
    check_interface_ip,
    check_ospf_enabled,
    check_ospf_interface,
    check_ospf_router_id,
    check_route_exists,
    check_service_vrf,
    check_snat_rule,
    check_ssh_key_configured,
    check_vrf_exists,
    check_vrf_interface,
    list_nat_rules,
)
            message="Test passed",
            raw_output="raw output",
        )

        assert result.passed is True
        assert result.message == "Test passed"
        assert result.raw_output == "raw output"

    def test_validation_result_failed(self) -> None:
        """Test ValidationResult with passed=False."""
        result = ValidationResult(
            passed=False,
            message="Test failed",
            raw_output="error output",
        )

        assert result.passed is False
        assert result.message == "Test failed"
        assert result.raw_output == "error output"


class TestCheckInterfaceIp:
    """Test check_interface_ip helper function."""

    def test_interface_ip_matches(self) -> None:
        """Test when interface has expected IP address."""
        mock_ssh = Mock(
            return_value=(
                "eth0@NONE: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                "    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff\n"
                "    inet 192.168.122.10/24 brd 192.168.122.255 scope global eth0\n"
                "       valid_lft forever preferred_lft forever\n"
            )
        )

        result = check_interface_ip(mock_ssh, "eth0", "192.168.122.10")

        assert result.passed is True
        assert "expected IP" in result.message
        assert "192.168.122.10" in result.message
        assert "eth0" in result.message
        mock_ssh.assert_called_once_with("show interfaces ethernet eth0")

    def test_interface_ip_mismatch(self) -> None:
        """Test when interface has different IP than expected."""
        mock_ssh = Mock(
            return_value=(
                "eth0@NONE: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                "    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff\n"
                "    inet 192.168.122.20/24 brd 192.168.122.255 scope global eth0\n"
            )
        )

        result = check_interface_ip(mock_ssh, "eth0", "192.168.122.10")

        assert result.passed is False
        assert "mismatch" in result.message.lower()
        assert "192.168.122.10" in result.message  # expected
        assert "192.168.122.20" in result.message  # actual
        assert "192.168.122.20" in result.raw_output

    def test_interface_no_ip(self) -> None:
        """Test when interface has no IP address configured."""
        mock_ssh = Mock(
            return_value=(
                "eth1@NONE: <BROADCAST,MULTICAST> mtu 1500\n"
                "    link/ether 52:54:00:12:34:57 brd ff:ff:ff:ff:ff:ff\n"
            )
        )

        result = check_interface_ip(mock_ssh, "eth1", "192.168.1.1")

        assert result.passed is False
        assert "No IP address found" in result.message
        assert "eth1" in result.message

    def test_interface_query_fails(self) -> None:
        """Test when SSH command fails."""
        mock_ssh = Mock(side_effect=Exception("Connection timeout"))

        result = check_interface_ip(mock_ssh, "eth0", "192.168.122.10")

        assert result.passed is False
        assert "Failed to query" in result.message
        assert "eth0" in result.message
        assert result.raw_output == ""

    def test_interface_different_subnet(self) -> None:
        """Test IP validation across different subnet masks."""
        mock_ssh = Mock(
            return_value=(
                "eth0@NONE: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                "    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff\n"
                "    inet 10.0.0.1/8 brd 10.255.255.255 scope global eth0\n"
            )
        )

        result = check_interface_ip(mock_ssh, "eth0", "10.0.0.1")

        assert result.passed is True
        assert "10.0.0.1" in result.message

    def test_interface_multiple_ips_first_match(self) -> None:
        """Test when interface has multiple IPs and first one matches.

        Note: VyOS can have multiple IPs on one interface (secondary IPs).
        This helper checks if the expected IP is present, matching the first found.
        """
        mock_ssh = Mock(
            return_value=(
                "eth0@NONE: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                "    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff\n"
                "    inet 192.168.1.1/24 brd 192.168.1.255 scope global eth0\n"
                "    inet 192.168.1.2/24 brd 192.168.1.255 scope global secondary eth0\n"
            )
        )

        # Check for first IP
        result = check_interface_ip(mock_ssh, "eth0", "192.168.1.1")
        assert result.passed is True


class TestCheckHostname:
    """Test check_hostname helper function."""

    def test_hostname_matches_with_quotes(self) -> None:
        """Test when hostname matches (VyOS uses single quotes)."""
        mock_ssh = Mock(return_value="host-name 'test-simple'\n")

        result = check_hostname(mock_ssh, "test-simple")

        assert result.passed is True
        assert "matches" in result.message.lower()
        assert "test-simple" in result.message
        mock_ssh.assert_called_once_with("show configuration | grep host-name")

    def test_hostname_matches_without_quotes(self) -> None:
        """Test when hostname matches (no quotes in config)."""
        mock_ssh = Mock(return_value="host-name test-router\n")

        result = check_hostname(mock_ssh, "test-router")

        assert result.passed is True
        assert "test-router" in result.message

    def test_hostname_mismatch(self) -> None:
        """Test when hostname does not match."""
        mock_ssh = Mock(return_value="host-name 'actual-name'\n")

        result = check_hostname(mock_ssh, "expected-name")

        assert result.passed is False
        assert "mismatch" in result.message.lower()
        assert "expected-name" in result.message
        assert "actual-name" in result.message

    def test_hostname_not_found(self) -> None:
        """Test when no hostname is configured."""
        mock_ssh = Mock(return_value="")

        result = check_hostname(mock_ssh, "test-router")

        assert result.passed is False
        assert "No hostname found" in result.message

    def test_hostname_query_fails(self) -> None:
        """Test when SSH command fails."""
        mock_ssh = Mock(side_effect=Exception("Connection error"))

        result = check_hostname(mock_ssh, "test-router")

        assert result.passed is False
        assert "Failed to query hostname" in result.message
        assert result.raw_output == ""

    def test_hostname_with_hyphens(self) -> None:
        """Test hostname validation with hyphens."""
        mock_ssh = Mock(return_value="host-name 'test-router-01'\n")

        result = check_hostname(mock_ssh, "test-router-01")

        assert result.passed is True

    def test_hostname_with_numbers(self) -> None:
        """Test hostname validation with numbers."""
        mock_ssh = Mock(return_value="host-name 'router123'\n")

        result = check_hostname(mock_ssh, "router123")

        assert result.passed is True

    def test_hostname_with_underscores(self) -> None:
        """Test that hostnames with underscores are rejected per RFC 952/1123."""
        mock_ssh = Mock(return_value="host-name 'test_router'\n")

        result = check_hostname(mock_ssh, "test_router")

        # Per RFC 952/1123, hostnames cannot contain underscores
        # The regex should fail to match the hostname part
        assert result.passed is False
        assert "No hostname found" in result.message
