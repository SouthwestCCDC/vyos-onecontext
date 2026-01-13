"""Smoke tests exercising full context parsing pipeline.

These tests validate end-to-end parsing from realistic context files to RouterConfig,
covering common deployment patterns. Each test class represents a deployment scenario.
"""

from pathlib import Path

import pytest

from vyos_onecontext.generators import generate_config
from vyos_onecontext.models import OnecontextMode
from vyos_onecontext.parser import parse_context

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestSimpleRouter:
    """Test simple single-interface router configuration.

    Scenario: Basic router with one interface, gateway, and SSH key.
    This is the minimal realistic deployment pattern.
    """

    @pytest.fixture
    def config(self):
        """Parse simple router context file."""
        return parse_context(str(FIXTURES_DIR / "simple_router.env"))

    def test_parse_succeeds(self, config) -> None:
        """Context file parses without errors."""
        assert config is not None

    def test_hostname_parsed(self, config) -> None:
        """Hostname is correctly parsed."""
        assert config.hostname == "simple-router"

    def test_onecontext_mode(self, config) -> None:
        """Onecontext mode is stateless."""
        assert config.onecontext_mode == OnecontextMode.STATELESS

    def test_ssh_key_parsed(self, config) -> None:
        """SSH public key is correctly parsed."""
        assert config.ssh_public_key is not None
        assert "ssh-ed25519" in config.ssh_public_key
        assert "admin@simple-router" in config.ssh_public_key

    def test_single_interface(self, config) -> None:
        """Single interface is parsed correctly."""
        assert len(config.interfaces) == 1
        iface = config.interfaces[0]
        assert iface.name == "eth0"
        assert str(iface.ip) == "192.168.1.1"
        assert iface.mask == "255.255.255.0"
        assert str(iface.gateway) == "192.168.1.254"
        assert str(iface.dns) == "8.8.8.8"

    def test_no_optional_features(self, config) -> None:
        """Optional features are not present."""
        assert len(config.aliases) == 0
        assert config.routes is None
        assert config.ospf is None
        assert config.dhcp is None
        assert config.nat is None
        assert config.firewall is None
        assert config.start_config is None
        assert config.start_script is None

    def test_generate_commands(self, config) -> None:
        """Command generation produces expected output."""
        commands = generate_config(config)

        # Should have hostname, SSH key (2 commands), and interface address
        assert len(commands) >= 3

        # Verify hostname command
        assert any("host-name" in cmd and "simple-router" in cmd for cmd in commands)

        # Verify SSH key command
        assert any("public-keys" in cmd for cmd in commands)

        # Verify interface command
        assert any(
            "eth0" in cmd and "192.168.1.1/24" in cmd for cmd in commands
        )

    def test_command_format(self, config) -> None:
        """Generated commands have correct VyOS format."""
        commands = generate_config(config)

        for cmd in commands:
            assert cmd.startswith("set "), f"Command should start with 'set': {cmd}"


class TestNatGateway:
    """Test NAT gateway configuration.

    Scenario: Two interfaces with NAT masquerading, port forwarding,
    DHCP server, and static routes.
    """

    @pytest.fixture
    def config(self):
        """Parse NAT gateway context file."""
        return parse_context(str(FIXTURES_DIR / "nat_gateway.env"))

    def test_parse_succeeds(self, config) -> None:
        """Context file parses without errors."""
        assert config is not None

    def test_hostname_parsed(self, config) -> None:
        """Hostname is correctly parsed."""
        assert config.hostname == "nat-gateway"

    def test_two_interfaces(self, config) -> None:
        """Both interfaces are parsed correctly."""
        assert len(config.interfaces) == 2

        # External interface
        eth0 = next(i for i in config.interfaces if i.name == "eth0")
        assert str(eth0.ip) == "203.0.113.10"
        assert str(eth0.gateway) == "203.0.113.1"

        # Internal interface
        eth1 = next(i for i in config.interfaces if i.name == "eth1")
        assert str(eth1.ip) == "10.0.1.1"
        assert eth1.gateway is None

    def test_static_routes(self, config) -> None:
        """Static routes are parsed correctly."""
        assert config.routes is not None
        assert len(config.routes.static) == 1

        route = config.routes.static[0]
        assert route.interface == "eth0"
        assert route.destination == "10.100.0.0/16"
        assert str(route.gateway) == "203.0.113.5"
        assert route.distance == 10

    def test_source_nat(self, config) -> None:
        """Source NAT (masquerade) is configured."""
        assert config.nat is not None
        assert len(config.nat.source) == 1

        snat = config.nat.source[0]
        assert snat.outbound_interface == "eth0"
        assert snat.source_address == "10.0.1.0/24"
        assert snat.translation == "masquerade"
        assert snat.description == "Masquerade internal network"

    def test_destination_nat(self, config) -> None:
        """Destination NAT (port forward) is configured."""
        assert config.nat is not None
        assert len(config.nat.destination) == 1

        dnat = config.nat.destination[0]
        assert dnat.inbound_interface == "eth0"
        assert dnat.protocol == "tcp"
        assert dnat.destination_port == 2222
        assert str(dnat.translation_address) == "10.0.1.100"
        assert dnat.translation_port == 22
        assert dnat.description == "SSH to internal server"

    def test_dhcp_pool(self, config) -> None:
        """DHCP pool is configured correctly."""
        assert config.dhcp is not None
        assert len(config.dhcp.pools) == 1

        pool = config.dhcp.pools[0]
        assert pool.interface == "eth1"
        assert pool.subnet == "10.0.1.0/24"
        assert str(pool.range_start) == "10.0.1.100"
        assert str(pool.range_end) == "10.0.1.200"
        assert str(pool.gateway) == "10.0.1.1"
        assert len(pool.dns) == 2
        assert pool.lease_time == 3600
        assert pool.domain == "internal.local"

    def test_dhcp_reservation(self, config) -> None:
        """DHCP reservation is configured correctly."""
        assert config.dhcp is not None
        assert len(config.dhcp.reservations) == 1

        res = config.dhcp.reservations[0]
        assert res.interface == "eth1"
        assert res.mac == "00:11:22:33:44:55"
        assert str(res.ip) == "10.0.1.50"
        assert res.hostname == "reserved-host"

    def test_cross_reference_validation(self, config) -> None:
        """Cross-reference validation passes.

        NAT rules reference existing interfaces,
        DHCP pools and reservations reference existing interfaces.
        """
        # If we got here, validation passed during parsing
        # Explicitly check interface names match
        interface_names = {i.name for i in config.interfaces}
        assert config.nat.source[0].outbound_interface in interface_names
        assert config.nat.destination[0].inbound_interface in interface_names
        assert config.dhcp.pools[0].interface in interface_names
        for reservation in config.dhcp.reservations:
            assert reservation.interface in interface_names

    def test_generate_commands(self, config) -> None:
        """Command generation produces expected output."""
        commands = generate_config(config)

        # Should have commands for hostname, SSH key, and interfaces
        assert len(commands) >= 4

        # Verify interface commands
        assert any("eth0" in cmd and "203.0.113.10/24" in cmd for cmd in commands)
        assert any("eth1" in cmd and "10.0.1.1/24" in cmd for cmd in commands)


class TestFullFeatured:
    """Test full-featured configuration with all options.

    Scenario: Three interfaces with management VRF, aliases, OSPF,
    firewall zones, multiple NAT types, DHCP, routes, and START_CONFIG.
    """

    @pytest.fixture
    def config(self):
        """Parse full-featured context file."""
        return parse_context(str(FIXTURES_DIR / "full_featured.env"))

    def test_parse_succeeds(self, config) -> None:
        """Context file parses without errors."""
        assert config is not None

    def test_hostname_parsed(self, config) -> None:
        """Hostname is correctly parsed."""
        assert config.hostname == "full-featured-router"

    def test_three_interfaces(self, config) -> None:
        """All three interfaces are parsed correctly."""
        assert len(config.interfaces) == 3

        eth0 = next(i for i in config.interfaces if i.name == "eth0")
        eth1 = next(i for i in config.interfaces if i.name == "eth1")
        eth2 = next(i for i in config.interfaces if i.name == "eth2")

        # Management interface
        assert str(eth0.ip) == "10.255.0.1"
        assert eth0.management is True
        assert eth0.mtu == 1500

        # External interface with gateway
        assert str(eth1.ip) == "198.51.100.1"
        assert str(eth1.gateway) == "198.51.100.254"

        # Internal interface
        assert str(eth2.ip) == "172.16.0.1"
        assert eth2.mask == "255.255.0.0"

    def test_aliases(self, config) -> None:
        """NIC aliases are parsed correctly."""
        assert len(config.aliases) == 2

        alias0 = next(a for a in config.aliases if str(a.ip) == "198.51.100.10")
        alias1 = next(a for a in config.aliases if str(a.ip) == "198.51.100.11")

        assert alias0.interface == "eth1"
        assert alias1.interface == "eth1"
        assert alias0.mask == "255.255.255.0"
        assert alias1.mask == "255.255.255.0"

    def test_static_routes(self, config) -> None:
        """Static routes with various options are parsed."""
        assert config.routes is not None
        assert len(config.routes.static) == 2

        # Route with custom distance
        route1 = next(
            r for r in config.routes.static if r.destination == "192.0.2.0/24"
        )
        assert route1.interface == "eth1"
        assert str(route1.gateway) == "198.51.100.2"
        assert route1.distance == 5

        # Route with default distance
        route2 = next(
            r for r in config.routes.static if r.destination == "172.20.0.0/16"
        )
        assert route2.interface == "eth2"
        assert route2.distance == 1

    def test_ospf_config(self, config) -> None:
        """OSPF configuration is parsed correctly."""
        assert config.ospf is not None
        assert config.ospf.enabled is True
        assert str(config.ospf.router_id) == "10.255.0.1"

        # Interfaces
        assert len(config.ospf.interfaces) == 2

        ospf_eth1 = next(i for i in config.ospf.interfaces if i.name == "eth1")
        assert ospf_eth1.area == "0.0.0.0"
        assert ospf_eth1.passive is False
        assert ospf_eth1.cost == 10

        ospf_eth2 = next(i for i in config.ospf.interfaces if i.name == "eth2")
        assert ospf_eth2.area == "0.0.0.1"
        assert ospf_eth2.passive is True

        # Redistribution
        assert "connected" in config.ospf.redistribute
        assert "static" in config.ospf.redistribute

        # Default information
        assert config.ospf.default_information is not None
        assert config.ospf.default_information.originate is True
        assert config.ospf.default_information.always is True
        assert config.ospf.default_information.metric == 100

    def test_source_nat(self, config) -> None:
        """Source NAT is configured."""
        assert config.nat is not None
        assert len(config.nat.source) == 1

        snat = config.nat.source[0]
        assert snat.outbound_interface == "eth1"
        assert snat.source_address == "172.16.0.0/16"

    def test_destination_nat(self, config) -> None:
        """Multiple destination NAT rules are configured."""
        assert config.nat is not None
        assert len(config.nat.destination) == 2

        # HTTPS port forward
        https_dnat = next(
            d for d in config.nat.destination if d.destination_port == 443
        )
        assert str(https_dnat.translation_address) == "172.16.1.10"
        assert https_dnat.description == "HTTPS to web server"

        # SMTP port forward
        smtp_dnat = next(
            d for d in config.nat.destination if d.destination_port == 25
        )
        assert str(smtp_dnat.translation_address) == "172.16.1.20"

    def test_binat(self, config) -> None:
        """Bidirectional NAT rules are configured."""
        assert config.nat is not None
        assert len(config.nat.binat) == 2

        binat1 = next(
            b for b in config.nat.binat if str(b.external_address) == "198.51.100.10"
        )
        assert str(binat1.internal_address) == "172.16.2.10"
        assert binat1.interface == "eth1"
        assert binat1.description == "DB server binat"

        binat2 = next(
            b for b in config.nat.binat if str(b.external_address) == "198.51.100.11"
        )
        assert str(binat2.internal_address) == "172.16.2.11"

    def test_binat_external_address_validation(self, config) -> None:
        """Binat external addresses exist as aliases on the interface."""
        # This validation happens during parsing - if we got here, it passed
        alias_ips = {str(a.ip) for a in config.aliases}
        primary_ips = {str(i.ip) for i in config.interfaces}
        all_ips = alias_ips | primary_ips

        for binat in config.nat.binat:
            assert str(binat.external_address) in all_ips

    def test_dhcp_config(self, config) -> None:
        """DHCP pool and reservations are configured."""
        assert config.dhcp is not None
        assert len(config.dhcp.pools) == 1
        assert len(config.dhcp.reservations) == 2

        pool = config.dhcp.pools[0]
        assert pool.interface == "eth2"
        assert pool.domain == "internal.example.com"

    def test_firewall_groups(self, config) -> None:
        """Firewall groups are configured."""
        assert config.firewall is not None

        # Network groups
        assert "INTERNAL_NETS" in config.firewall.groups.network
        assert "172.16.0.0/16" in config.firewall.groups.network["INTERNAL_NETS"]
        assert "EXTERNAL_TRUSTED" in config.firewall.groups.network

        # Address groups
        assert "DNS_SERVERS" in config.firewall.groups.address
        assert "8.8.8.8" in config.firewall.groups.address["DNS_SERVERS"]

        # Port groups
        assert "WEB_PORTS" in config.firewall.groups.port
        assert 80 in config.firewall.groups.port["WEB_PORTS"]
        assert 443 in config.firewall.groups.port["WEB_PORTS"]

    def test_firewall_zones(self, config) -> None:
        """Firewall zones are configured correctly."""
        assert config.firewall is not None
        assert len(config.firewall.zones) == 3

        assert "WAN" in config.firewall.zones
        assert config.firewall.zones["WAN"].interfaces == ["eth1"]
        assert config.firewall.zones["WAN"].default_action == "drop"

        assert "LAN" in config.firewall.zones
        assert config.firewall.zones["LAN"].interfaces == ["eth2"]

        assert "MGMT" in config.firewall.zones
        assert config.firewall.zones["MGMT"].interfaces == ["eth0"]
        assert config.firewall.zones["MGMT"].default_action == "reject"

    def test_firewall_policies(self, config) -> None:
        """Firewall policies are configured."""
        assert config.firewall is not None
        assert len(config.firewall.policies) == 2

        # LAN to WAN policy
        lan_wan = next(
            p
            for p in config.firewall.policies
            if p.from_zone == "LAN" and p.to_zone == "WAN"
        )
        assert len(lan_wan.rules) == 3

        # Check rule with port group reference
        web_rule = next(r for r in lan_wan.rules if r.destination_port_group == "WEB_PORTS")
        assert web_rule.action == "accept"
        assert web_rule.protocol == "tcp"

        # Check ICMP rule
        icmp_rule = next(r for r in lan_wan.rules if r.protocol == "icmp")
        assert icmp_rule.icmp_type == "echo-request"

    def test_start_config(self, config) -> None:
        """START_CONFIG raw commands are parsed."""
        assert config.start_config is not None
        assert "set system option performance throughput" in config.start_config
        assert "set system time-zone UTC" in config.start_config

    def test_cross_reference_validation(self, config) -> None:
        """All cross-reference validations pass."""
        interface_names = {i.name for i in config.interfaces}

        # NAT interfaces
        assert config.nat.source[0].outbound_interface in interface_names
        for dnat in config.nat.destination:
            assert dnat.inbound_interface in interface_names
        for binat in config.nat.binat:
            assert binat.interface in interface_names

        # DHCP interfaces (pools and reservations)
        assert config.dhcp.pools[0].interface in interface_names
        for reservation in config.dhcp.reservations:
            assert reservation.interface in interface_names

        # Firewall zone interfaces
        for zone in config.firewall.zones.values():
            for iface in zone.interfaces:
                assert iface in interface_names

        # OSPF interfaces
        for ospf_iface in config.ospf.interfaces:
            assert ospf_iface.name in interface_names

        # Static route interfaces
        for route in config.routes.static:
            assert route.interface in interface_names

        # Alias parent interfaces
        for alias in config.aliases:
            assert alias.interface in interface_names

    def test_generate_commands(self, config) -> None:
        """Command generation produces output without errors."""
        commands = generate_config(config)

        # Should have multiple commands
        assert len(commands) > 0

        # All commands should be 'set' commands
        for cmd in commands:
            assert cmd.startswith("set ")

        # Verify interface commands
        assert any("eth0" in cmd for cmd in commands)
        assert any("eth1" in cmd for cmd in commands)
        assert any("eth2" in cmd for cmd in commands)

        # Verify aliases are included as additional addresses
        assert sum(1 for cmd in commands if "198.51.100" in cmd) >= 3


class TestEmptyContextFile:
    """Test behavior with empty context file."""

    def test_empty_file_parses(self, tmp_path) -> None:
        """Empty context file parses to minimal config."""
        context_file = tmp_path / "empty.env"
        context_file.write_text("")

        config = parse_context(str(context_file))

        assert config.hostname is None
        assert len(config.interfaces) == 0
        assert config.onecontext_mode == OnecontextMode.STATELESS

    def test_empty_file_generates_no_commands(self, tmp_path) -> None:
        """Empty config generates no commands."""
        context_file = tmp_path / "empty.env"
        context_file.write_text("")

        config = parse_context(str(context_file))
        commands = generate_config(config)

        assert len(commands) == 0


class TestInvalidContextFiles:
    """Test error handling for invalid context files."""

    def test_missing_file_raises_error(self) -> None:
        """Missing context file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            parse_context("/nonexistent/path/context.env")

    def test_invalid_interface_ref_in_nat(self, tmp_path) -> None:
        """NAT rule referencing non-existent interface raises error."""
        context_file = tmp_path / "invalid.env"
        content = """ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"

NAT_JSON='{"source": [{"outbound_interface": "eth99", "translation": "masquerade"}]}'
"""
        context_file.write_text(content)

        with pytest.raises(ValueError, match="non-existent outbound_interface"):
            parse_context(str(context_file))

    def test_invalid_interface_ref_in_dhcp(self, tmp_path) -> None:
        """DHCP pool referencing non-existent interface raises error."""
        context_file = tmp_path / "invalid.env"
        dhcp_json = (
            '{"pools": [{"interface": "eth99", "range_start": "10.0.1.100", '
            '"range_end": "10.0.1.200", "gateway": "10.0.1.1", "dns": ["8.8.8.8"]}]}'
        )
        content = f"""ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"

DHCP_JSON='{dhcp_json}'
"""
        context_file.write_text(content)

        with pytest.raises(ValueError, match="non-existent interface"):
            parse_context(str(context_file))

    def test_invalid_interface_ref_in_ospf(self, tmp_path) -> None:
        """OSPF config referencing non-existent interface raises error."""
        context_file = tmp_path / "invalid.env"
        content = """ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"

OSPF_JSON='{"enabled": true, "interfaces": [{"name": "eth99", "area": "0.0.0.0"}]}'
"""
        context_file.write_text(content)

        with pytest.raises(ValueError, match="non-existent interface"):
            parse_context(str(context_file))

    def test_invalid_interface_ref_in_firewall(self, tmp_path) -> None:
        """Firewall zone referencing non-existent interface raises error."""
        context_file = tmp_path / "invalid.env"
        fw_json = (
            '{"zones": {"WAN": {"name": "WAN", "interfaces": ["eth99"], '
            '"default_action": "drop"}}, "policies": []}'
        )
        content = f"""ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"

FIREWALL_JSON='{fw_json}'
"""
        context_file.write_text(content)

        with pytest.raises(ValueError, match="non-existent interface"):
            parse_context(str(context_file))

    def test_binat_external_not_on_interface(self, tmp_path) -> None:
        """Binat with external address not on interface raises error."""
        context_file = tmp_path / "invalid.env"
        nat_json = (
            '{"binat": [{"external_address": "192.168.1.100", '
            '"internal_address": "10.0.1.50", "interface": "eth0"}]}'
        )
        content = f"""ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"

NAT_JSON='{nat_json}'
"""
        context_file.write_text(content)

        with pytest.raises(ValueError, match="not configured on interface"):
            parse_context(str(context_file))

    def test_malformed_json(self, tmp_path) -> None:
        """Malformed JSON raises error."""
        context_file = tmp_path / "invalid.env"
        content = """ROUTES_JSON='{"invalid": json}'
"""
        context_file.write_text(content)

        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_context(str(context_file))
