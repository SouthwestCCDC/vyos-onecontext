"""Comprehensive tests for Pydantic models."""

import pytest
from pydantic import ValidationError

from vyos_onecontext.models import (
    AliasConfig,
    BinatRule,
    DestinationNatRule,
    DhcpConfig,
    DhcpPool,
    DhcpReservation,
    FirewallConfig,
    FirewallGroups,
    FirewallPolicy,
    FirewallRule,
    FirewallZone,
    InterfaceConfig,
    NatConfig,
    OnecontextMode,
    OspfConfig,
    OspfDefaultInformation,
    OspfInterface,
    RouterConfig,
    RoutesConfig,
    SourceNatRule,
    StaticRoute,
)


class TestInterfaceConfig:
    """Tests for InterfaceConfig model."""

    def test_valid_interface(self):
        """Test valid interface configuration."""
        iface = InterfaceConfig(
            name="eth0",
            ip="10.0.1.1",
            mask="255.255.255.0",
            gateway="10.0.1.254",
            dns="8.8.8.8",
            mtu=1500,
            management=True,
        )
        assert iface.name == "eth0"
        assert str(iface.ip) == "10.0.1.1"
        assert iface.mask == "255.255.255.0"
        assert iface.to_prefix_length() == 24
        assert iface.to_cidr() == "10.0.1.1/24"

    def test_minimal_interface(self):
        """Test minimal interface configuration."""
        iface = InterfaceConfig(name="eth0", ip="10.0.1.1", mask="255.255.255.0")
        assert iface.gateway is None
        assert iface.dns is None
        assert iface.mtu is None
        assert iface.management is False

    def test_invalid_netmask_format(self):
        """Test that invalid netmask format is rejected."""
        with pytest.raises(ValidationError, match="dotted-decimal"):
            InterfaceConfig(name="eth0", ip="10.0.1.1", mask="24")

    def test_invalid_netmask_value(self):
        """Test that invalid netmask value is rejected."""
        with pytest.raises(ValidationError, match="contiguous"):
            InterfaceConfig(name="eth0", ip="10.0.1.1", mask="255.255.0.255")

    def test_mtu_bounds(self):
        """Test MTU validation bounds."""
        # Valid MTU
        InterfaceConfig(name="eth0", ip="10.0.1.1", mask="255.255.255.0", mtu=1500)

        # MTU too small
        with pytest.raises(ValidationError):
            InterfaceConfig(name="eth0", ip="10.0.1.1", mask="255.255.255.0", mtu=67)

        # MTU too large
        with pytest.raises(ValidationError):
            InterfaceConfig(name="eth0", ip="10.0.1.1", mask="255.255.255.0", mtu=9001)


class TestAliasConfig:
    """Tests for AliasConfig model."""

    def test_valid_alias(self):
        """Test valid alias configuration."""
        alias = AliasConfig(interface="eth0", ip="10.0.1.2", mask="255.255.255.0")
        assert alias.interface == "eth0"
        assert str(alias.ip) == "10.0.1.2"
        assert alias.to_prefix_length("255.255.255.0") == 24

    def test_alias_with_none_mask(self):
        """Test alias with None mask (OpenNebula bug workaround)."""
        alias = AliasConfig(interface="eth0", ip="10.0.1.2", mask=None)
        assert alias.mask is None
        # Should use fallback mask
        assert alias.to_cidr("255.255.255.0") == "10.0.1.2/24"

    def test_alias_with_empty_mask(self):
        """Test alias with empty string mask."""
        alias = AliasConfig(interface="eth0", ip="10.0.1.2", mask="")
        assert alias.mask is None


class TestStaticRoute:
    """Tests for StaticRoute model."""

    def test_valid_route_with_gateway(self):
        """Test valid static route with gateway."""
        route = StaticRoute(
            interface="eth1", destination="0.0.0.0/0", gateway="10.0.1.254", distance=10
        )
        assert route.interface == "eth1"
        assert route.destination == "0.0.0.0/0"
        assert str(route.gateway) == "10.0.1.254"
        assert route.distance == 10

    def test_interface_route_without_gateway(self):
        """Test interface route without gateway."""
        route = StaticRoute(interface="eth1", destination="192.168.0.0/16")
        assert route.gateway is None
        assert route.distance == 1  # default

    def test_route_with_vrf(self):
        """Test route with VRF."""
        route = StaticRoute(
            interface="eth0", destination="10.0.0.0/8", gateway="10.1.1.1", vrf="management"
        )
        assert route.vrf == "management"

    def test_invalid_cidr(self):
        """Test that invalid CIDR is rejected."""
        with pytest.raises(ValidationError, match="Invalid CIDR"):
            StaticRoute(interface="eth1", destination="10.0.0.0/33")

    def test_distance_bounds(self):
        """Test distance validation bounds."""
        with pytest.raises(ValidationError):
            StaticRoute(interface="eth1", destination="0.0.0.0/0", distance=0)

        with pytest.raises(ValidationError):
            StaticRoute(interface="eth1", destination="0.0.0.0/0", distance=256)


class TestOspfConfig:
    """Tests for OSPF models."""

    def test_valid_ospf_interface(self):
        """Test valid OSPF interface."""
        iface = OspfInterface(name="eth1", area="0.0.0.0", passive=False, cost=100)
        assert iface.name == "eth1"
        assert iface.area == "0.0.0.0"
        assert iface.passive is False
        assert iface.cost == 100

    def test_ospf_interface_minimal(self):
        """Test minimal OSPF interface."""
        iface = OspfInterface(name="eth1", area="0.0.0.0")
        assert iface.passive is False
        assert iface.cost is None

    def test_ospf_area_integer_format(self):
        """Test OSPF area integer format conversion."""
        iface = OspfInterface(name="eth1", area="0")
        assert iface.area == "0.0.0.0"

        iface2 = OspfInterface(name="eth1", area="1")
        assert iface2.area == "0.0.0.1"

    def test_valid_ospf_config(self):
        """Test valid OSPF configuration."""
        ospf = OspfConfig(
            enabled=True,
            router_id="10.0.0.1",
            interfaces=[
                OspfInterface(name="eth1", area="0.0.0.0"),
                OspfInterface(name="eth2", area="0.0.0.0", passive=True),
            ],
            redistribute=["connected", "static"],
            default_information=OspfDefaultInformation(originate=True, always=True, metric=100),
        )
        assert ospf.enabled is True
        assert str(ospf.router_id) == "10.0.0.1"
        assert len(ospf.interfaces) == 2
        assert "connected" in ospf.redistribute


class TestDhcpConfig:
    """Tests for DHCP models."""

    def test_valid_dhcp_pool(self):
        """Test valid DHCP pool."""
        pool = DhcpPool(
            interface="eth1",
            subnet="10.1.1.0/24",
            range_start="10.1.1.100",
            range_end="10.1.1.200",
            gateway="10.1.1.1",
            dns=["10.1.1.1", "8.8.8.8"],
            lease_time=86400,
            domain="example.local",
        )
        assert pool.interface == "eth1"
        assert pool.subnet == "10.1.1.0/24"
        assert len(pool.dns) == 2

    def test_dhcp_pool_without_subnet(self):
        """Test DHCP pool without explicit subnet (auto-derived)."""
        pool = DhcpPool(
            interface="eth1",
            range_start="10.1.1.100",
            range_end="10.1.1.200",
            gateway="10.1.1.1",
            dns=["10.1.1.1"],
        )
        assert pool.subnet is None

    def test_dhcp_range_order(self):
        """Test DHCP range order validation."""
        with pytest.raises(ValidationError, match="greater than"):
            DhcpPool(
                interface="eth1",
                range_start="10.1.1.200",
                range_end="10.1.1.100",
                gateway="10.1.1.1",
                dns=["10.1.1.1"],
            )

    def test_valid_dhcp_reservation(self):
        """Test valid DHCP reservation."""
        reservation = DhcpReservation(
            interface="eth1", mac="00:11:22:33:44:55", ip="10.1.1.50", hostname="server01"
        )
        assert reservation.mac == "00:11:22:33:44:55"
        assert str(reservation.ip) == "10.1.1.50"

    def test_mac_address_formats(self):
        """Test various MAC address formats."""
        # Colon-separated
        r1 = DhcpReservation(interface="eth1", mac="00:11:22:33:44:55", ip="10.1.1.50")
        assert r1.mac == "00:11:22:33:44:55"

        # Dash-separated
        r2 = DhcpReservation(interface="eth1", mac="00-11-22-33-44-55", ip="10.1.1.50")
        assert r2.mac == "00:11:22:33:44:55"

        # Bare format
        r3 = DhcpReservation(interface="eth1", mac="001122334455", ip="10.1.1.50")
        assert r3.mac == "00:11:22:33:44:55"

    def test_invalid_mac_address(self):
        """Test invalid MAC address."""
        with pytest.raises(ValidationError, match="MAC address"):
            DhcpReservation(interface="eth1", mac="invalid", ip="10.1.1.50")


class TestNatConfig:
    """Tests for NAT models."""

    def test_source_nat_masquerade(self):
        """Test source NAT with masquerade."""
        rule = SourceNatRule(
            outbound_interface="eth0",
            source_address="10.0.0.0/8",
            translation="masquerade",
            description="Masquerade internal traffic",
        )
        assert rule.outbound_interface == "eth0"
        assert rule.translation == "masquerade"

    def test_source_nat_static(self):
        """Test source NAT with static address."""
        rule = SourceNatRule(
            outbound_interface="eth0",
            source_address="192.168.0.0/16",
            translation_address="203.0.113.10",
        )
        assert rule.translation_address == "203.0.113.10"

    def test_destination_nat_port_forward(self):
        """Test destination NAT for port forwarding."""
        rule = DestinationNatRule(
            inbound_interface="eth0",
            protocol="tcp",
            destination_port=443,
            translation_address="10.62.0.20",
            translation_port=443,
            description="HTTPS to web server",
        )
        assert rule.protocol == "tcp"
        assert rule.destination_port == 443

    def test_destination_nat_icmp_no_port(self):
        """Test that ICMP destination NAT rejects port."""
        with pytest.raises(ValidationError, match="not valid for ICMP"):
            DestinationNatRule(
                inbound_interface="eth0",
                protocol="icmp",
                destination_port=443,
                translation_address="10.62.0.20",
            )

    def test_binat_rule(self):
        """Test bidirectional NAT rule."""
        rule = BinatRule(
            external_address="129.244.246.66",
            internal_address="10.63.0.101",
            interface="eth0",
            description="Scoring engine",
        )
        assert str(rule.external_address) == "129.244.246.66"
        assert str(rule.internal_address) == "10.63.0.101"

    def test_nat_config_complete(self):
        """Test complete NAT configuration."""
        nat = NatConfig(
            source=[
                SourceNatRule(
                    outbound_interface="eth0", source_address="10.0.0.0/8", translation="masquerade"
                )
            ],
            destination=[
                DestinationNatRule(
                    inbound_interface="eth0",
                    protocol="tcp",
                    destination_port=443,
                    translation_address="10.62.0.20",
                )
            ],
            binat=[
                BinatRule(
                    external_address="129.244.246.66",
                    internal_address="10.63.0.101",
                    interface="eth0",
                )
            ],
        )
        assert len(nat.source) == 1
        assert len(nat.destination) == 1
        assert len(nat.binat) == 1


class TestFirewallConfig:
    """Tests for firewall models."""

    def test_firewall_groups(self):
        """Test firewall groups."""
        groups = FirewallGroups(
            network={"GAME": ["10.64.0.0/10", "10.128.0.0/9"], "SCORING": ["10.62.0.0/16"]},
            address={"SCORING_ENGINE": ["10.63.0.101"], "DNS_SERVERS": ["10.63.4.101", "8.8.8.8"]},
            port={"WEB": [80, 443], "SSH": [22]},
        )
        assert "GAME" in groups.network
        assert len(groups.network["GAME"]) == 2
        assert 80 in groups.port["WEB"]

    def test_firewall_groups_invalid_cidr(self):
        """Test that invalid CIDR in network group is rejected."""
        with pytest.raises(ValidationError, match="Invalid CIDR"):
            FirewallGroups(network={"BAD": ["10.0.0.0/33"]})

    def test_firewall_groups_invalid_port(self):
        """Test that invalid port in port group is rejected."""
        with pytest.raises(ValidationError, match="must be 1-65535"):
            FirewallGroups(port={"BAD": [80, 99999]})

    def test_firewall_rule(self):
        """Test firewall rule."""
        rule = FirewallRule(
            action="accept",
            protocol="tcp",
            destination_port_group="WEB",
            description="Allow web traffic",
        )
        assert rule.action == "accept"
        assert rule.protocol == "tcp"

    def test_firewall_rule_icmp_type(self):
        """Test ICMP firewall rule."""
        rule = FirewallRule(
            action="accept", protocol="icmp", icmp_type="echo-request", description="Allow ping"
        )
        assert rule.protocol == "icmp"
        assert rule.icmp_type == "echo-request"

    def test_firewall_rule_icmp_type_without_icmp(self):
        """Test that icmp_type requires icmp protocol."""
        with pytest.raises(ValidationError, match="only be used with protocol='icmp'"):
            FirewallRule(action="accept", protocol="tcp", icmp_type="echo-request")

    def test_firewall_zone(self):
        """Test firewall zone."""
        zone = FirewallZone(name="WAN", interfaces=["eth0"], default_action="drop")
        assert zone.name == "WAN"
        assert "eth0" in zone.interfaces
        assert zone.default_action == "drop"

    def test_firewall_zone_reject_accept(self):
        """Test that zone default_action cannot be accept."""
        with pytest.raises(ValidationError, match="Input should be 'drop' or 'reject'"):
            FirewallZone(name="WAN", interfaces=["eth0"], default_action="accept")

    def test_firewall_policy(self):
        """Test firewall policy."""
        policy = FirewallPolicy(
            from_zone="GAME",
            to_zone="SCORING",
            rules=[
                FirewallRule(
                    action="accept", protocol="tcp", destination_port_group="WEB", description="Web"
                )
            ],
        )
        assert policy.from_zone == "GAME"
        assert policy.to_zone == "SCORING"
        assert len(policy.rules) == 1

    def test_complete_firewall_config(self):
        """Test complete firewall configuration."""
        fw = FirewallConfig(
            groups=FirewallGroups(
                network={"GAME": ["10.64.0.0/10"]},
                address={"SCORING_ENGINE": ["10.63.0.101"]},
                port={"WEB": [80, 443]},
            ),
            zones={
                "WAN": FirewallZone(name="WAN", interfaces=["eth0"], default_action="drop"),
                "GAME": FirewallZone(name="GAME", interfaces=["eth1"], default_action="drop"),
            },
            policies=[
                FirewallPolicy(
                    from_zone="GAME",
                    to_zone="WAN",
                    rules=[FirewallRule(action="accept", description="Allow all")],
                )
            ],
        )
        assert "WAN" in fw.zones
        assert len(fw.policies) == 1


class TestRouterConfig:
    """Tests for top-level RouterConfig."""

    def test_minimal_router_config(self):
        """Test minimal router configuration."""
        router = RouterConfig()
        assert router.hostname is None
        assert router.onecontext_mode == OnecontextMode.STATELESS
        assert len(router.interfaces) == 0

    def test_complete_router_config(self):
        """Test complete router configuration."""
        router = RouterConfig(
            hostname="router-01",
            ssh_public_key="ssh-rsa AAAA...",
            onecontext_mode=OnecontextMode.FREEZE,
            interfaces=[InterfaceConfig(name="eth0", ip="10.0.1.1", mask="255.255.255.0")],
            routes=RoutesConfig(
                static=[
                    StaticRoute(interface="eth1", destination="0.0.0.0/0", gateway="10.0.1.254")
                ]
            ),
            ospf=OspfConfig(
                enabled=True,
                router_id="10.0.0.1",
                interfaces=[OspfInterface(name="eth1", area="0.0.0.0")],
            ),
            dhcp=DhcpConfig(
                pools=[
                    DhcpPool(
                        interface="eth1",
                        range_start="10.1.1.100",
                        range_end="10.1.1.200",
                        gateway="10.1.1.1",
                        dns=["10.1.1.1"],
                    )
                ]
            ),
            nat=NatConfig(
                source=[
                    SourceNatRule(
                        outbound_interface="eth0",
                        source_address="10.0.0.0/8",
                        translation="masquerade",
                    )
                ]
            ),
            firewall=FirewallConfig(
                zones={
                    "WAN": FirewallZone(name="WAN", interfaces=["eth0"], default_action="drop")
                }
            ),
        )
        assert router.hostname == "router-01"
        assert router.onecontext_mode == OnecontextMode.FREEZE
        assert len(router.interfaces) == 1
        assert router.routes is not None
        assert router.ospf is not None
        assert router.dhcp is not None
        assert router.nat is not None
        assert router.firewall is not None


class TestOnecontextMode:
    """Tests for OnecontextMode enum."""

    def test_mode_values(self):
        """Test OnecontextMode enum values."""
        assert OnecontextMode.STATELESS.value == "stateless"
        assert OnecontextMode.SAVE.value == "save"
        assert OnecontextMode.FREEZE.value == "freeze"

    def test_mode_in_router_config(self):
        """Test mode assignment in router config."""
        r1 = RouterConfig(onecontext_mode=OnecontextMode.STATELESS)
        assert r1.onecontext_mode == OnecontextMode.STATELESS

        r2 = RouterConfig(onecontext_mode=OnecontextMode.FREEZE)
        assert r2.onecontext_mode == OnecontextMode.FREEZE


class TestJsonSerialization:
    """Tests for JSON serialization and deserialization."""

    def test_routes_config_json_roundtrip(self):
        """Test RoutesConfig JSON serialization roundtrip."""
        routes = RoutesConfig(
            static=[
                StaticRoute(interface="eth1", destination="0.0.0.0/0", gateway="10.0.1.254"),
                StaticRoute(interface="eth2", destination="192.168.0.0/16", vrf="management"),
            ]
        )
        json_str = routes.model_dump_json()
        routes_loaded = RoutesConfig.model_validate_json(json_str)
        assert len(routes_loaded.static) == 2
        assert routes_loaded.static[0].interface == "eth1"

    def test_ospf_config_json_roundtrip(self):
        """Test OspfConfig JSON serialization roundtrip."""
        ospf = OspfConfig(
            enabled=True,
            router_id="10.0.0.1",
            interfaces=[
                OspfInterface(name="eth1", area="0.0.0.0"),
                OspfInterface(name="eth2", area="0.0.0.0", passive=True, cost=100),
            ],
            redistribute=["connected", "static"],
        )
        json_str = ospf.model_dump_json()
        ospf_loaded = OspfConfig.model_validate_json(json_str)
        assert ospf_loaded.enabled is True
        assert len(ospf_loaded.interfaces) == 2

    def test_dhcp_config_json_roundtrip(self):
        """Test DhcpConfig JSON serialization roundtrip."""
        dhcp = DhcpConfig(
            pools=[
                DhcpPool(
                    interface="eth1",
                    range_start="10.1.1.100",
                    range_end="10.1.1.200",
                    gateway="10.1.1.1",
                    dns=["10.1.1.1"],
                )
            ],
            reservations=[
                DhcpReservation(interface="eth1", mac="00:11:22:33:44:55", ip="10.1.1.50")
            ],
        )
        json_str = dhcp.model_dump_json()
        dhcp_loaded = DhcpConfig.model_validate_json(json_str)
        assert len(dhcp_loaded.pools) == 1
        assert len(dhcp_loaded.reservations) == 1

    def test_nat_config_json_roundtrip(self):
        """Test NatConfig JSON serialization roundtrip."""
        nat = NatConfig(
            source=[
                SourceNatRule(
                    outbound_interface="eth0", source_address="10.0.0.0/8", translation="masquerade"
                )
            ],
            destination=[
                DestinationNatRule(
                    inbound_interface="eth0",
                    protocol="tcp",
                    destination_port=443,
                    translation_address="10.62.0.20",
                )
            ],
            binat=[
                BinatRule(
                    external_address="129.244.246.66",
                    internal_address="10.63.0.101",
                    interface="eth0",
                )
            ],
        )
        json_str = nat.model_dump_json()
        nat_loaded = NatConfig.model_validate_json(json_str)
        assert len(nat_loaded.source) == 1
        assert len(nat_loaded.destination) == 1
        assert len(nat_loaded.binat) == 1

    def test_firewall_config_json_roundtrip(self):
        """Test FirewallConfig JSON serialization roundtrip."""
        fw = FirewallConfig(
            groups=FirewallGroups(
                network={"GAME": ["10.64.0.0/10"]},
                address={"SERVER": ["10.0.1.1"]},
                port={"WEB": [80]},
            ),
            zones={
                "WAN": FirewallZone(name="WAN", interfaces=["eth0"], default_action="drop")
            },
            policies=[
                FirewallPolicy(
                    from_zone="GAME",
                    to_zone="WAN",
                    rules=[FirewallRule(action="accept", description="Test")],
                )
            ],
        )
        json_str = fw.model_dump_json()
        fw_loaded = FirewallConfig.model_validate_json(json_str)
        assert "GAME" in fw_loaded.groups.network
        assert "WAN" in fw_loaded.zones
