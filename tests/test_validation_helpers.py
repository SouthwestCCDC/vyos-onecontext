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
        """Test hostname validation rejects underscores (per RFC 952/1123)."""
        mock_ssh = Mock(return_value="host-name 'test_router'\n")

        result = check_hostname(mock_ssh, "test_router")

        # Hostname with underscore will match only the part before underscore
        # This causes a mismatch: expected "test_router", got "test"
        assert result.passed is False
        assert "Hostname mismatch" in result.message
        assert "expected test_router, got test" in result.message


class TestCheckSshKeyConfigured:
    """Test check_ssh_key_configured helper function."""

    def test_ssh_key_present(self) -> None:
        """Test when SSH public keys are configured."""
        mock_ssh = Mock(
            return_value=(
                "    public-keys test-key-1 {\n"
                "        key AAAAB3NzaC1yc2EAAAADAQABAAABAQC...\n"
                "        type ssh-rsa\n"
                "    }\n"
            )
        )

        result = check_ssh_key_configured(mock_ssh)

        assert result.passed is True
        assert "SSH public key(s) found" in result.message
        mock_ssh.assert_called_once_with("show configuration | grep 'public-keys' || echo ''")

    def test_ssh_key_not_configured(self) -> None:
        """Test when no SSH keys are configured."""
        mock_ssh = Mock(return_value="")

        result = check_ssh_key_configured(mock_ssh)

        assert result.passed is False
        assert "No SSH public keys configured" in result.message

    def test_ssh_key_multiple_keys(self) -> None:
        """Test when multiple SSH keys are configured."""
        mock_ssh = Mock(
            return_value=(
                "    public-keys test-key-1 {\n"
                "        key AAAAB3NzaC1yc2EAAAADAQABAAABAQC...\n"
                "        type ssh-rsa\n"
                "    }\n"
                "    public-keys test-key-2 {\n"
                "        key AAAAC3NzaC1lZDI1NTE5AAAAIN...\n"
                "        type ssh-ed25519\n"
                "    }\n"
            )
        )

        result = check_ssh_key_configured(mock_ssh)

        assert result.passed is True
        assert "SSH public key(s) found" in result.message

    def test_ssh_key_malformed_config(self) -> None:
        """Test when public-keys stanza exists but is incomplete."""
        # Stanza found but missing key data or type
        mock_ssh = Mock(return_value="    public-keys test-key-1 {\n    }\n")

        result = check_ssh_key_configured(mock_ssh)

        assert result.passed is False
        assert "missing key data or type" in result.message

    def test_ssh_key_query_fails(self) -> None:
        """Test when SSH command fails."""
        mock_ssh = Mock(side_effect=Exception("SSH connection lost"))

        result = check_ssh_key_configured(mock_ssh)

        assert result.passed is False
        assert "Failed to query SSH key configuration" in result.message
        assert result.raw_output == ""

    def test_ssh_key_ed25519_type(self) -> None:
        """Test with ed25519 key type."""
        mock_ssh = Mock(
            return_value=(
                "    public-keys test-ed25519 {\n"
                "        key AAAAC3NzaC1lZDI1NTE5AAAAIN...\n"
                "        type ssh-ed25519\n"
                "    }\n"
            )
        )

        result = check_ssh_key_configured(mock_ssh)

        assert result.passed is True

    def test_ssh_key_rsa_type(self) -> None:
        """Test with RSA key type."""
        mock_ssh = Mock(
            return_value=(
                "    public-keys test-rsa {\n"
                "        key AAAAB3NzaC1yc2EAAAADAQABAAABAQC...\n"
                "        type ssh-rsa\n"
                "    }\n"
            )
        )

        result = check_ssh_key_configured(mock_ssh)

        assert result.passed is True

    def test_ssh_key_with_full_config_output(self) -> None:
        """Test with full VyOS config output containing other settings."""
        mock_ssh = Mock(
            return_value=(
                "system {\n"
                "    login {\n"
                "        user vyos {\n"
                "            authentication {\n"
                "                public-keys test-key {\n"
                "                    key AAAAB3NzaC1yc2EAAAADAQABAAABAQC...\n"
                "                    type ssh-rsa\n"
                "                }\n"
                "            }\n"
                "        }\n"
                "    }\n"
                "}\n"
            )
        )

        result = check_ssh_key_configured(mock_ssh)

        assert result.passed is True
        assert "public-keys" in result.raw_output


class TestCheckOspfEnabled:
    """Test check_ospf_enabled helper function."""

    def test_ospf_enabled_and_running(self) -> None:
        """Test when OSPF process is running."""
        mock_ssh = Mock(
            return_value=(
                "OSPF Routing Process, Router ID: 192.168.122.70\n"
                "Supports only single TOS (TOS0) routes\n"
                "This implementation conforms to RFC2328\n"
                "RFC1583Compatibility flag is disabled\n"
                "OpaqueCapability flag is disabled\n"
                "Initial SPF scheduling delay 0 millisec(s)\n"
            )
        )

        result = check_ospf_enabled(mock_ssh)

        assert result.passed is True
        assert "OSPF routing process is running" in result.message
        assert "OSPF Routing Process" in result.raw_output
        mock_ssh.assert_called_once_with("show ip ospf || echo ''")

    def test_ospf_not_running(self) -> None:
        """Test when OSPF is not configured or running."""
        mock_ssh = Mock(return_value="% OSPF instance not found\n")

        result = check_ospf_enabled(mock_ssh)

        assert result.passed is False
        assert "OSPF routing process is not running" in result.message

    def test_ospf_empty_output(self) -> None:
        """Test when command returns empty output (OSPF not configured)."""
        mock_ssh = Mock(return_value="")

        result = check_ospf_enabled(mock_ssh)

        assert result.passed is False
        assert "OSPF routing process is not running" in result.message

    def test_ospf_query_fails(self) -> None:
        """Test when SSH command fails."""
        mock_ssh = Mock(side_effect=Exception("Connection timeout"))

        result = check_ospf_enabled(mock_ssh)

        assert result.passed is False
        assert "Failed to query OSPF status" in result.message
        assert result.raw_output == ""

    def test_ospf_unexpected_output(self) -> None:
        """Test when output format is unexpected."""
        mock_ssh = Mock(return_value="Some unexpected output\n")

        result = check_ospf_enabled(mock_ssh)

        assert result.passed is False
        assert "Unable to determine OSPF status" in result.message


class TestCheckOspfRouterId:
    """Test check_ospf_router_id helper function."""

    def test_router_id_matches(self) -> None:
        """Test when router ID matches expected value."""
        mock_ssh = Mock(
            return_value=(
                "OSPF Routing Process, Router ID: 192.168.122.70\n"
                "Supports only single TOS (TOS0) routes\n"
                "This implementation conforms to RFC2328\n"
            )
        )

        result = check_ospf_router_id(mock_ssh, "192.168.122.70")

        assert result.passed is True
        assert "OSPF router ID matches expected value" in result.message
        assert "192.168.122.70" in result.message
        mock_ssh.assert_called_once_with("show ip ospf")

    def test_router_id_mismatch(self) -> None:
        """Test when router ID does not match expected value."""
        mock_ssh = Mock(
            return_value=(
                "OSPF Routing Process, Router ID: 10.0.0.1\n"
                "Supports only single TOS (TOS0) routes\n"
            )
        )

        result = check_ospf_router_id(mock_ssh, "192.168.122.70")

        assert result.passed is False
        assert "OSPF router ID mismatch" in result.message
        assert "192.168.122.70" in result.message  # expected
        assert "10.0.0.1" in result.message  # actual

    def test_router_id_ospf_not_running(self) -> None:
        """Test when OSPF is not running."""
        mock_ssh = Mock(return_value="% OSPF instance not found\n")

        result = check_ospf_router_id(mock_ssh, "192.168.122.70")

        assert result.passed is False
        assert "OSPF is not running" in result.message

    def test_router_id_not_found_in_output(self) -> None:
        """Test when output doesn't contain router ID."""
        mock_ssh = Mock(return_value="Some output without router ID\n")

        result = check_ospf_router_id(mock_ssh, "192.168.122.70")

        assert result.passed is False
        assert "No OSPF router ID found" in result.message

    def test_router_id_query_fails(self) -> None:
        """Test when SSH command fails."""
        mock_ssh = Mock(side_effect=Exception("Network error"))

        result = check_ospf_router_id(mock_ssh, "192.168.122.70")

        assert result.passed is False
        assert "Failed to query OSPF router ID" in result.message
        assert result.raw_output == ""

    def test_router_id_different_formats(self) -> None:
        """Test router ID validation with different IP formats."""
        mock_ssh = Mock(
            return_value="OSPF Routing Process, Router ID: 10.255.255.254\n"
        )

        result = check_ospf_router_id(mock_ssh, "10.255.255.254")

        assert result.passed is True

    def test_router_id_auto_derived(self) -> None:
        """Test when VyOS auto-derives router ID from interface."""
        # VyOS can auto-derive router ID if not explicitly set
        mock_ssh = Mock(
            return_value="OSPF Routing Process, Router ID: 192.168.1.1\n"
        )

        result = check_ospf_router_id(mock_ssh, "192.168.1.1")

        assert result.passed is True


class TestCheckOspfInterface:
    """Test check_ospf_interface helper function."""

    def test_interface_configured_with_area_match(self) -> None:
        """Test when interface is configured in OSPF with matching area."""
        mock_ssh = Mock(
            return_value=(
                "set protocols ospf interface eth0 area '0.0.0.0'\n"
                "set protocols ospf interface eth0 passive\n"
                "set protocols ospf parameters router-id '192.168.122.70'\n"
            )
        )

        result = check_ospf_interface(mock_ssh, "eth0", "0.0.0.0")

        assert result.passed is True
        assert "Interface eth0 is in OSPF area 0.0.0.0" in result.message
        mock_ssh.assert_called_once_with("show configuration commands | grep ospf || echo ''")

    def test_interface_configured_area_mismatch(self) -> None:
        """Test when interface is in OSPF but area doesn't match."""
        mock_ssh = Mock(
            return_value=(
                "set protocols ospf interface eth0 area '1.1.1.1'\n"
                "set protocols ospf parameters router-id '192.168.122.70'\n"
            )
        )

        result = check_ospf_interface(mock_ssh, "eth0", "0.0.0.0")

        assert result.passed is False
        assert "Interface eth0 area mismatch" in result.message
        assert "0.0.0.0" in result.message  # expected
        assert "1.1.1.1" in result.message  # actual

    def test_interface_not_in_ospf(self) -> None:
        """Test when interface is not configured in OSPF."""
        mock_ssh = Mock(
            return_value=(
                "set protocols ospf interface eth1 area '0.0.0.0'\n"
                "set protocols ospf parameters router-id '192.168.122.70'\n"
            )
        )

        result = check_ospf_interface(mock_ssh, "eth0", "0.0.0.0")

        assert result.passed is False
        assert "Interface eth0 is not configured in OSPF" in result.message

    def test_interface_configured_no_area_check(self) -> None:
        """Test checking if interface is in OSPF without validating area."""
        mock_ssh = Mock(
            return_value=(
                "set protocols ospf interface eth0 area '1.2.3.4'\n"
                "set protocols ospf parameters router-id '192.168.122.70'\n"
            )
        )

        # area=None means just check if interface is in OSPF
        result = check_ospf_interface(mock_ssh, "eth0", area=None)

        assert result.passed is True
        assert "Interface eth0 is configured in OSPF" in result.message
        assert "1.2.3.4" in result.message  # Should report the actual area

    def test_interface_query_fails(self) -> None:
        """Test when SSH command fails."""
        mock_ssh = Mock(side_effect=Exception("SSH error"))

        result = check_ospf_interface(mock_ssh, "eth0", "0.0.0.0")

        assert result.passed is False
        assert "Failed to query OSPF configuration" in result.message
        assert result.raw_output == ""

    def test_interface_area_without_quotes(self) -> None:
        """Test when area is configured without quotes."""
        mock_ssh = Mock(
            return_value=(
                "set protocols ospf interface eth0 area 0.0.0.0\n"
                "set protocols ospf parameters router-id '192.168.122.70'\n"
            )
        )

        result = check_ospf_interface(mock_ssh, "eth0", "0.0.0.0")

        assert result.passed is True

    def test_interface_multiple_interfaces(self) -> None:
        """Test when multiple interfaces are configured in OSPF."""
        mock_ssh = Mock(
            return_value=(
                "set protocols ospf interface eth0 area '0.0.0.0'\n"
                "set protocols ospf interface eth1 area '0.0.0.1'\n"
                "set protocols ospf interface eth2 area '0.0.0.0'\n"
                "set protocols ospf parameters router-id '192.168.122.70'\n"
            )
        )

        # Check eth1 is in area 0.0.0.1
        result = check_ospf_interface(mock_ssh, "eth1", "0.0.0.1")
        assert result.passed is True

    def test_interface_with_additional_config(self) -> None:
        """Test interface with passive and cost configuration."""
        mock_ssh = Mock(
            return_value=(
                "set protocols ospf interface eth0 area '0.0.0.0'\n"
                "set protocols ospf interface eth0 cost '100'\n"
                "set protocols ospf interface eth0 passive\n"
                "set protocols ospf parameters router-id '192.168.122.70'\n"
            )
        )

        result = check_ospf_interface(mock_ssh, "eth0", "0.0.0.0")

        assert result.passed is True
        assert "passive" in result.raw_output
        assert "cost" in result.raw_output

    def test_interface_name_escaping(self) -> None:
        """Test interface name with special characters is properly escaped."""
        # VyOS can have interface names like eth0.100 (VLAN interfaces)
        mock_ssh = Mock(
            return_value=(
                "set protocols ospf interface eth0.100 area '0.0.0.0'\n"
                "set protocols ospf parameters router-id '192.168.122.70'\n"
            )
        )

        result = check_ospf_interface(mock_ssh, "eth0.100", "0.0.0.0")

        assert result.passed is True

    def test_interface_backbone_area(self) -> None:
        """Test with OSPF backbone area (0.0.0.0)."""
        mock_ssh = Mock(
            return_value="set protocols ospf interface eth0 area '0.0.0.0'\n"
        )

        result = check_ospf_interface(mock_ssh, "eth0", "0.0.0.0")

        assert result.passed is True

    def test_interface_non_backbone_area(self) -> None:
        """Test with non-backbone OSPF area."""
        mock_ssh = Mock(
            return_value="set protocols ospf interface eth0 area '10.20.30.40'\n"
        )

        result = check_ospf_interface(mock_ssh, "eth0", "10.20.30.40")

        assert result.passed is True


class TestCheckRouteExists:
    """Test check_route_exists helper function."""

    def test_gateway_route_exists(self) -> None:
        """Test when gateway route exists with expected parameters."""
        mock_ssh = Mock(
            return_value=(
                "Routing entry for 10.0.0.0/8\n"
                "  Known via \"static\", distance 1, metric 0, best\n"
                "  Last update 00:01:00 ago\n"
                "  * 192.168.122.1, via eth0\n"
                "\n"
                "S>* 10.0.0.0/8 [1/0] via 192.168.122.1, eth0, weight 1, 00:01:00\n"
            )
        )

        result = check_route_exists(
            mock_ssh,
            destination="10.0.0.0/8",
            via="192.168.122.1",
            interface="eth0",
        )

        assert result.passed is True
        assert "via 192.168.122.1" in result.message
        assert "interface eth0" in result.message
        assert "10.0.0.0/8" in result.message
        mock_ssh.assert_called_once_with("show ip route 10.0.0.0/8")

    def test_interface_route_exists(self) -> None:
        """Test when interface route (directly connected) exists."""
        mock_ssh = Mock(
            return_value=(
                "Routing entry for 172.16.0.0/12\n"
                "  Known via \"static\", distance 1, metric 0, best\n"
                "  Last update 00:01:00 ago\n"
                "  * directly connected, eth0\n"
                "\n"
                "S>* 172.16.0.0/12 [1/0] is directly connected, eth0, weight 1, 00:01:00\n"
            )
        )

        result = check_route_exists(
            mock_ssh,
            destination="172.16.0.0/12",
            interface="eth0",
        )

        assert result.passed is True
        assert "interface eth0" in result.message
        assert "172.16.0.0/12" in result.message
        # Should not mention "via" for interface routes
        assert "via" not in result.message.lower()

    def test_route_not_found(self) -> None:
        """Test when route does not exist in routing table."""
        mock_ssh = Mock(return_value="% Network not in table\n")

        result = check_route_exists(
            mock_ssh,
            destination="192.168.99.0/24",
            via="192.168.122.1",
        )

        assert result.passed is False
        assert "not found" in result.message.lower()
        assert "192.168.99.0/24" in result.message

    def test_route_gateway_mismatch(self) -> None:
        """Test when route exists but gateway doesn't match."""
        mock_ssh = Mock(
            return_value="S>* 10.0.0.0/8 [1/0] via 192.168.122.254, eth0, weight 1, 00:01:00\n"
        )

        result = check_route_exists(
            mock_ssh,
            destination="10.0.0.0/8",
            via="192.168.122.1",  # Expected gateway
        )

        assert result.passed is False
        assert "gateway mismatch" in result.message
        assert "192.168.122.1" in result.message  # expected
        assert "192.168.122.254" in result.message  # actual

    def test_route_interface_mismatch(self) -> None:
        """Test when route exists but interface doesn't match."""
        mock_ssh = Mock(
            return_value="S>* 10.0.0.0/8 [1/0] via 192.168.122.1, eth1, weight 1, 00:01:00\n"
        )

        result = check_route_exists(
            mock_ssh,
            destination="10.0.0.0/8",
            interface="eth0",  # Expected interface
        )

        assert result.passed is False
        assert "interface mismatch" in result.message
        assert "eth0" in result.message  # expected
        assert "eth1" in result.message  # actual

    def test_route_both_mismatch(self) -> None:
        """Test when both gateway and interface mismatch."""
        mock_ssh = Mock(
            return_value="S>* 10.0.0.0/8 [1/0] via 192.168.122.254, eth1, weight 1, 00:01:00\n"
        )

        result = check_route_exists(
            mock_ssh,
            destination="10.0.0.0/8",
            via="192.168.122.1",
            interface="eth0",
        )

        assert result.passed is False
        assert "gateway mismatch" in result.message
        assert "interface mismatch" in result.message

    def test_route_query_fails(self) -> None:
        """Test when SSH command fails."""
        mock_ssh = Mock(side_effect=Exception("Connection timeout"))

        result = check_route_exists(
            mock_ssh,
            destination="10.0.0.0/8",
            via="192.168.122.1",
        )

        assert result.passed is False
        assert "Failed to query route" in result.message
        assert "10.0.0.0/8" in result.message
        assert result.raw_output == ""

    def test_route_unparseable_output(self) -> None:
        """Test when route exists but output format is unexpected."""
        mock_ssh = Mock(
            return_value="10.0.0.0/8 some unexpected format\n"
        )

        result = check_route_exists(
            mock_ssh,
            destination="10.0.0.0/8",
            via="192.168.122.1",
        )

        assert result.passed is False
        assert "could not parse" in result.message.lower()

    def test_route_only_destination_check(self) -> None:
        """Test checking only if destination exists (no via/interface validation)."""
        mock_ssh = Mock(
            return_value="S>* 10.0.0.0/8 [1/0] via 192.168.122.1, eth0, weight 1, 00:01:00\n"
        )

        result = check_route_exists(
            mock_ssh,
            destination="10.0.0.0/8",
        )

        assert result.passed is True
        assert "exists" in result.message
        assert "10.0.0.0/8" in result.message

    def test_route_gateway_only_validation(self) -> None:
        """Test validating only gateway (no interface check)."""
        mock_ssh = Mock(
            return_value="S>* 10.0.0.0/8 [1/0] via 192.168.122.1, eth0, weight 1, 00:01:00\n"
        )

        result = check_route_exists(
            mock_ssh,
            destination="10.0.0.0/8",
            via="192.168.122.1",
        )

        assert result.passed is True
        assert "via 192.168.122.1" in result.message

    def test_route_interface_only_validation(self) -> None:
        """Test validating only interface (no gateway check)."""
        mock_ssh = Mock(
            return_value="S>* 172.16.0.0/12 [1/0] is directly connected, eth0, weight 1, 00:01:00\n"
        )

        result = check_route_exists(
            mock_ssh,
            destination="172.16.0.0/12",
            interface="eth0",
        )

        assert result.passed is True
        assert "interface eth0" in result.message

    def test_route_invalid_cidr_missing_prefix(self) -> None:
        """Test that bare IP addresses without prefix are rejected."""
        mock_ssh = Mock()

        result = check_route_exists(
            mock_ssh,
            destination="10.0.0.1",  # Missing /32 or other prefix
        )

        assert result.passed is False
        assert "Invalid destination CIDR" in result.message
        assert "must include prefix length" in result.message
        # SSH should not be called if validation fails early
        mock_ssh.assert_not_called()

    def test_route_invalid_cidr_format(self) -> None:
        """Test that invalid CIDR notation is rejected."""
        mock_ssh = Mock()

        result = check_route_exists(
            mock_ssh,
            destination="10.0.0.0/999",  # Invalid prefix length
        )

        assert result.passed is False
        assert "Invalid destination CIDR" in result.message
        mock_ssh.assert_not_called()

    def test_route_invalid_gateway_ip(self) -> None:
        """Test that invalid gateway IP addresses are rejected."""
        mock_ssh = Mock()

        result = check_route_exists(
            mock_ssh,
            destination="10.0.0.0/8",
            via="999.999.999.999",  # Invalid IP
        )

        assert result.passed is False
        assert "Invalid gateway IP" in result.message
        mock_ssh.assert_not_called()

    def test_route_ipv6_gateway_rejected(self) -> None:
        """Test that IPv6 gateway addresses are rejected for IPv4 routes."""
        mock_ssh = Mock()

        result = check_route_exists(
            mock_ssh,
            destination="10.0.0.0/8",
            via="2001:db8::1",  # IPv6 address
        )

        assert result.passed is False
        assert "Invalid gateway IP" in result.message
        assert "IPv6 addresses not supported" in result.message
        mock_ssh.assert_not_called()

    def test_route_vti_interface(self) -> None:
        """Test route validation with VTI interface names (vti@NONE)."""
        mock_ssh = Mock(
            return_value="S>* 10.0.0.0/8 [1/0] via 192.168.1.1, vti@NONE, weight 1, 00:01:00\n"
        )

        result = check_route_exists(
            mock_ssh,
            destination="10.0.0.0/8",
            via="192.168.1.1",
            interface="vti@NONE",
        )

        assert result.passed is True
        assert "via 192.168.1.1" in result.message
        assert "interface vti@NONE" in result.message

    def test_route_ecmp_multiple_gateways(self) -> None:
        """Test ECMP route validation with multiple next-hops."""
        mock_ssh = Mock(
            return_value=(
                "Routing entry for 10.0.0.0/8\n"
                "  Known via \"static\", distance 1, metric 0, best\n"
                "S>* 10.0.0.0/8 [1/0] via 192.168.122.1, eth0, weight 1, 00:01:00\n"
                "S>* 10.0.0.0/8 [1/0] via 192.168.122.2, eth1, weight 1, 00:01:00\n"
            )
        )

        # Should match first gateway
        result = check_route_exists(
            mock_ssh,
            destination="10.0.0.0/8",
            via="192.168.122.1",
        )
        assert result.passed is True
        assert "via 192.168.122.1" in result.message

        # Should also match second gateway
        result = check_route_exists(
            mock_ssh,
            destination="10.0.0.0/8",
            via="192.168.122.2",
        )
        assert result.passed is True
        assert "via 192.168.122.2" in result.message

        # Should fail if gateway not in ECMP set
        result = check_route_exists(
            mock_ssh,
            destination="10.0.0.0/8",
            via="192.168.122.3",
        )
        assert result.passed is False
        assert "gateway mismatch" in result.message
        assert "192.168.122.1" in result.message
        assert "192.168.122.2" in result.message


class TestCheckDefaultRoute:
    """Test check_default_route helper function."""

    def test_default_route_exists(self) -> None:
        """Test when default route exists."""
        mock_ssh = Mock(
            return_value=(
                "Routing entry for 0.0.0.0/0\n"
                "  Known via \"static\", distance 1, metric 0, best\n"
                "  Last update 00:05:23 ago\n"
                "  * 192.168.122.1, via eth0\n"
                "\n"
                "S>* 0.0.0.0/0 [1/0] via 192.168.122.1, eth0, weight 1, 00:05:23\n"
            )
        )

        result = check_default_route(mock_ssh)

        assert result.passed is True
        assert "Default route exists" in result.message
        mock_ssh.assert_called_once_with("show ip route 0.0.0.0/0")

    def test_default_route_with_gateway(self) -> None:
        """Test when default route exists with expected gateway."""
        mock_ssh = Mock(
            return_value="S>* 0.0.0.0/0 [1/0] via 192.168.122.1, eth0, weight 1, 00:05:23\n"
        )

        result = check_default_route(mock_ssh, gateway="192.168.122.1")

        assert result.passed is True
        assert "via 192.168.122.1" in result.message

    def test_default_route_not_found(self) -> None:
        """Test when no default route exists."""
        mock_ssh = Mock(return_value="% Network not in table\n")

        result = check_default_route(mock_ssh)

        assert result.passed is False
        assert "not found" in result.message.lower()
        assert "0.0.0.0/0" in result.message

    def test_default_route_gateway_mismatch(self) -> None:
        """Test when default route exists but gateway doesn't match."""
        mock_ssh = Mock(
            return_value="S>* 0.0.0.0/0 [1/0] via 192.168.122.254, eth0, weight 1, 00:05:23\n"
        )

        result = check_default_route(mock_ssh, gateway="192.168.122.1")

        assert result.passed is False
        assert "gateway mismatch" in result.message
        assert "192.168.122.1" in result.message  # expected
        assert "192.168.122.254" in result.message  # actual

    def test_default_route_query_fails(self) -> None:
        """Test when SSH command fails."""
        mock_ssh = Mock(side_effect=Exception("Network error"))

        result = check_default_route(mock_ssh)

        assert result.passed is False
        assert "Failed to query default route" in result.message
        assert result.raw_output == ""

    def test_default_route_unparseable_gateway(self) -> None:
        """Test when default route exists but gateway cannot be parsed."""
        mock_ssh = Mock(
            return_value="0.0.0.0/0 some unexpected format\n"
        )

        result = check_default_route(mock_ssh, gateway="192.168.122.1")

        assert result.passed is False
        assert "could not parse gateway" in result.message

    def test_default_route_no_gateway_validation(self) -> None:
        """Test checking default route exists without validating gateway."""
        mock_ssh = Mock(
            return_value="S>* 0.0.0.0/0 [1/0] via 10.0.0.1, eth0, weight 1, 00:05:23\n"
        )

        result = check_default_route(mock_ssh)

        assert result.passed is True
        assert "Default route exists" in result.message

    def test_default_route_invalid_gateway_ip(self) -> None:
        """Test that invalid gateway IP addresses are rejected."""
        mock_ssh = Mock()

        result = check_default_route(mock_ssh, gateway="999.999.999.999")

        assert result.passed is False
        assert "Invalid gateway IP" in result.message
        mock_ssh.assert_not_called()

    def test_default_route_ipv6_gateway_rejected(self) -> None:
        """Test that IPv6 gateway addresses are rejected."""
        mock_ssh = Mock()

        result = check_default_route(mock_ssh, gateway="2001:db8::1")

        assert result.passed is False
        assert "Invalid gateway IP" in result.message
        assert "IPv6 addresses not supported" in result.message
        mock_ssh.assert_not_called()

    def test_default_route_ecmp_multiple_gateways(self) -> None:
        """Test ECMP default route with multiple next-hops."""
        mock_ssh = Mock(
            return_value=(
                "Routing entry for 0.0.0.0/0\n"
                "  Known via \"static\", distance 1, metric 0, best\n"
                "S>* 0.0.0.0/0 [1/0] via 192.168.122.1, eth0, weight 1, 00:05:23\n"
                "S>* 0.0.0.0/0 [1/0] via 192.168.122.2, eth1, weight 1, 00:05:23\n"
            )
        )

        # Should match first gateway
        result = check_default_route(mock_ssh, gateway="192.168.122.1")
        assert result.passed is True
        assert "via 192.168.122.1" in result.message

        # Should also match second gateway
        result = check_default_route(mock_ssh, gateway="192.168.122.2")
        assert result.passed is True
        assert "via 192.168.122.2" in result.message

        # Should fail if gateway not in ECMP set
        result = check_default_route(mock_ssh, gateway="192.168.122.3")
        assert result.passed is False
        assert "gateway mismatch" in result.message
        assert "192.168.122.1" in result.message
        assert "192.168.122.2" in result.message


class TestCheckVrfExists:
    """Test check_vrf_exists helper function."""

    def test_vrf_exists_without_table_id(self) -> None:
        """Test when VRF exists and no table ID validation requested."""
        mock_ssh = Mock(
            return_value=(
                "--------          -----     -----------        -----            ----------\n"
                "mgmt              up        aa:bb:cc:dd:ee:ff  noarp,master     eth0\n"
            )
        )

        result = check_vrf_exists(mock_ssh, "mgmt")

        assert result.passed is True
        assert "VRF 'mgmt' exists" in result.message
        mock_ssh.assert_called_once_with("show vrf")

    def test_vrf_exists_with_matching_table_id(self) -> None:
        """Test when VRF exists with correct table ID."""
        mock_ssh = Mock()
        # First call returns VRF list, second call returns VRF details
        mock_ssh.side_effect = [
            (
                "VRF name          state     mac address        flags            interfaces\n"
                "--------          -----     -----------        -----            ----------\n"
                "mgmt              up        aa:bb:cc:dd:ee:ff  noarp,master     eth0\n"
            ),
            ("VRF: mgmt\n  Table: 1000\n  Interfaces:\n    eth0\n"),
        ]

        result = check_vrf_exists(mock_ssh, "mgmt", table_id=1000)

        assert result.passed is True
        assert "VRF 'mgmt' exists with table ID 1000" in result.message
        assert mock_ssh.call_count == 2
        mock_ssh.assert_any_call("show vrf")
        mock_ssh.assert_any_call("show vrf name mgmt")

    def test_vrf_not_found(self) -> None:
        """Test when VRF does not exist."""
        mock_ssh = Mock(
            return_value=(
                "VRF name          state     mac address        flags            interfaces\n"
                "--------          -----     -----------        -----            ----------\n"
                "other             up        aa:bb:cc:dd:ee:ff  noarp,master     eth1\n"
            )
        )

        result = check_vrf_exists(mock_ssh, "mgmt")

        assert result.passed is False
        assert "VRF 'mgmt' not found" in result.message

    def test_vrf_table_id_mismatch(self) -> None:
        """Test when VRF exists but table ID doesn't match."""
        mock_ssh = Mock()
        mock_ssh.side_effect = [
            (
                "VRF name          state     mac address        flags            interfaces\n"
                "--------          -----     -----------        -----            ----------\n"
                "mgmt              up        aa:bb:cc:dd:ee:ff  noarp,master     eth0\n"
            ),
            ("VRF: mgmt\n  Table: 2000\n  Interfaces:\n    eth0\n"),
        ]

        result = check_vrf_exists(mock_ssh, "mgmt", table_id=1000)

        assert result.passed is False
        assert "table ID mismatch" in result.message
        assert "expected 1000" in result.message
        assert "got 2000" in result.message

    def test_vrf_query_fails(self) -> None:
        """Test when show vrf command fails."""
        mock_ssh = Mock(side_effect=Exception("Connection lost"))

        result = check_vrf_exists(mock_ssh, "mgmt")

        assert result.passed is False
        assert "Failed to query VRF list" in result.message
        assert result.raw_output == ""

    def test_vrf_detail_query_fails(self) -> None:
        """Test when VRF exists but detail query fails."""
        mock_ssh = Mock()
        mock_ssh.side_effect = [
            (
                "VRF name          state     mac address        flags            interfaces\n"
                "--------          -----     -----------        -----            ----------\n"
                "mgmt              up        aa:bb:cc:dd:ee:ff  noarp,master     eth0\n"
            ),
            Exception("Permission denied"),
        ]

        result = check_vrf_exists(mock_ssh, "mgmt", table_id=1000)

        assert result.passed is False
        assert "Failed to query VRF 'mgmt' details" in result.message

    def test_vrf_no_table_in_details(self) -> None:
        """Test when VRF details don't contain table ID."""
        mock_ssh = Mock()
        mock_ssh.side_effect = [
            (
                "VRF name          state     mac address        flags            interfaces\n"
                "--------          -----     -----------        -----            ----------\n"
                "mgmt              up        aa:bb:cc:dd:ee:ff  noarp,master     eth0\n"
            ),
            ("VRF: mgmt\n  Interfaces:\n    eth0\n"),
        ]

        result = check_vrf_exists(mock_ssh, "mgmt", table_id=1000)

        assert result.passed is False
        assert "table ID not found in details" in result.message

    def test_vrf_multiple_vrfs_in_list(self) -> None:
        """Test finding specific VRF among multiple VRFs."""
        mock_ssh = Mock(
            return_value=(
                "VRF name          state     mac address        flags            interfaces\n"
                "--------          -----     -----------        -----            ----------\n"
                "blue              up        aa:bb:cc:dd:ee:01  noarp,master     eth1\n"
                "mgmt              up        aa:bb:cc:dd:ee:ff  noarp,master     eth0\n"
                "red               up        aa:bb:cc:dd:ee:02  noarp,master     eth2\n"
            )
        )

        result = check_vrf_exists(mock_ssh, "mgmt")

        assert result.passed is True
        assert "VRF 'mgmt' exists" in result.message

    def test_vrf_name_with_hyphens(self) -> None:
        """Test VRF name containing hyphens."""
        mock_ssh = Mock(
            return_value=(
                "VRF name          state     mac address        flags            interfaces\n"
                "--------          -----     -----------        -----            ----------\n"
                "my-vrf-1          up        aa:bb:cc:dd:ee:ff  noarp,master     eth0\n"
            )
        )

        result = check_vrf_exists(mock_ssh, "my-vrf-1")

        assert result.passed is True


class TestCheckVrfInterface:
    """Test check_vrf_interface helper function."""

    def test_interface_in_vrf(self) -> None:
        """Test when interface is correctly bound to VRF."""
        mock_ssh = Mock(return_value=("VRF: mgmt\n  Table: 1000\n  Interfaces:\n    eth0\n"))

        result = check_vrf_interface(mock_ssh, "mgmt", "eth0")

        assert result.passed is True
        assert "Interface eth0 is bound to VRF 'mgmt'" in result.message
        mock_ssh.assert_called_once_with("show vrf name mgmt")

    def test_interface_not_in_vrf(self) -> None:
        """Test when interface is not in the VRF."""
        mock_ssh = Mock(return_value=("VRF: mgmt\n  Table: 1000\n  Interfaces:\n    eth0\n"))

        result = check_vrf_interface(mock_ssh, "mgmt", "eth1")

        assert result.passed is False
        assert "Interface eth1 not found in VRF 'mgmt'" in result.message

    def test_vrf_no_interfaces(self) -> None:
        """Test when VRF exists but has no interfaces."""
        mock_ssh = Mock(return_value=("VRF: mgmt\n  Table: 1000\n"))

        result = check_vrf_interface(mock_ssh, "mgmt", "eth0")

        assert result.passed is False
        assert "has no interfaces listed" in result.message

    def test_vrf_multiple_interfaces(self) -> None:
        """Test finding interface among multiple interfaces in VRF."""
        mock_ssh = Mock(
            return_value=("VRF: mgmt\n  Table: 1000\n  Interfaces:\n    eth0\n    eth1\n    eth2\n")
        )

        result = check_vrf_interface(mock_ssh, "mgmt", "eth1")

        assert result.passed is True
        assert "eth1" in result.message

    def test_vrf_query_fails(self) -> None:
        """Test when VRF query fails."""
        mock_ssh = Mock(side_effect=Exception("VRF not found"))

        result = check_vrf_interface(mock_ssh, "mgmt", "eth0")

        assert result.passed is False
        assert "Failed to query VRF 'mgmt'" in result.message
        assert result.raw_output == ""

    def test_interface_with_vlan(self) -> None:
        """Test interface with VLAN subinterface."""
        mock_ssh = Mock(return_value=("VRF: mgmt\n  Table: 1000\n  Interfaces:\n    eth0.100\n"))

        result = check_vrf_interface(mock_ssh, "mgmt", "eth0.100")

        assert result.passed is True

    def test_vrf_empty_interfaces_list(self) -> None:
        """Test when VRF has Interfaces: section but it's empty."""
        mock_ssh = Mock(return_value=("VRF: mgmt\n  Table: 1000\n  Interfaces:\n"))

        result = check_vrf_interface(mock_ssh, "mgmt", "eth0")

        assert result.passed is False
        assert "not found in VRF" in result.message


class TestCheckServiceVrf:
    """Test check_service_vrf helper function."""

    def test_service_bound_to_vrf_with_quotes(self) -> None:
        """Test when service is correctly bound to VRF (with quotes)."""
        mock_ssh = Mock(return_value="set service ssh vrf 'mgmt'\n")

        result = check_service_vrf(mock_ssh, "ssh", "mgmt")

        assert result.passed is True
        assert "Service 'ssh' is bound to VRF 'mgmt'" in result.message
        mock_ssh.assert_called_once_with(
            "show configuration commands | grep 'service ssh vrf' || echo ''"
        )

    def test_service_bound_to_vrf_without_quotes(self) -> None:
        """Test when service is bound to VRF (no quotes)."""
        mock_ssh = Mock(return_value="set service ssh vrf mgmt\n")

        result = check_service_vrf(mock_ssh, "ssh", "mgmt")

        assert result.passed is True

    def test_service_no_vrf_binding(self) -> None:
        """Test when service has no VRF binding."""
        mock_ssh = Mock(return_value="")

        result = check_service_vrf(mock_ssh, "ssh", "mgmt")

        assert result.passed is False
        assert "Service 'ssh' has no VRF binding configured" in result.message

    def test_service_wrong_vrf(self) -> None:
        """Test when service is bound to different VRF."""
        mock_ssh = Mock(return_value="set service ssh vrf 'other'\n")

        result = check_service_vrf(mock_ssh, "ssh", "mgmt")

        assert result.passed is False
        assert "VRF mismatch" in result.message
        assert "expected 'mgmt'" in result.message
        assert "got 'other'" in result.message

    def test_service_query_fails(self) -> None:
        """Test when configuration query fails."""
        mock_ssh = Mock(side_effect=Exception("Access denied"))

        result = check_service_vrf(mock_ssh, "ssh", "mgmt")

        assert result.passed is False
        assert "Failed to query service 'ssh' VRF configuration" in result.message
        assert result.raw_output == ""

    def test_https_service(self) -> None:
        """Test HTTPS service VRF binding."""
        mock_ssh = Mock(return_value="set service https vrf 'mgmt'\n")

        result = check_service_vrf(mock_ssh, "https", "mgmt")

        assert result.passed is True
        assert "https" in result.message

    def test_snmp_service(self) -> None:
        """Test SNMP service VRF binding."""
        mock_ssh = Mock(return_value="set service snmp vrf 'mgmt'\n")

        result = check_service_vrf(mock_ssh, "snmp", "mgmt")

        assert result.passed is True

    def test_service_vrf_with_hyphens(self) -> None:
        """Test VRF name with hyphens."""
        mock_ssh = Mock(return_value="set service ssh vrf 'my-mgmt-vrf'\n")

        result = check_service_vrf(mock_ssh, "ssh", "my-mgmt-vrf")

        assert result.passed is True

    def test_service_multiple_config_lines(self) -> None:
        """Test when grep returns multiple service configurations."""
        # This might happen if there are multiple services or config contexts
        mock_ssh = Mock(
            return_value=(
                "set service ssh vrf 'mgmt'\nset service ssh listen-address '10.0.0.1'\n"
            )
        )

        result = check_service_vrf(mock_ssh, "ssh", "mgmt")

        assert result.passed is True

    def test_service_unparseable_vrf_config(self) -> None:
        """Test when VRF config exists but cannot parse VRF name."""
        # Edge case: malformed config that matches grep but not regex
        mock_ssh = Mock(return_value="set service ssh vrf\n")

        result = check_service_vrf(mock_ssh, "ssh", "mgmt")

        assert result.passed is False
        assert "cannot parse VRF name" in result.message
