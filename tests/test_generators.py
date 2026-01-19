"""Tests for VyOS command generators."""

from ipaddress import IPv4Address

from vyos_onecontext.generators import (
    VRF_NAME,
    VRF_TABLE_ID,
    HostnameGenerator,
    InterfaceGenerator,
    OspfGenerator,
    RoutingGenerator,
    SshKeyGenerator,
    SshServiceGenerator,
    VrfGenerator,
    generate_config,
)
from vyos_onecontext.models import (
    AliasConfig,
    InterfaceConfig,
    OspfConfig,
    OspfDefaultInformation,
    OspfInterface,
    RouterConfig,
)


class TestHostnameGenerator:
    """Tests for hostname configuration generator."""

    def test_generate_with_hostname(self):
        """Test hostname generation with valid hostname."""
        gen = HostnameGenerator("router-01")
        commands = gen.generate()

        assert len(commands) == 1
        assert commands[0] == "set system host-name router-01"

    def test_generate_without_hostname(self):
        """Test hostname generation with None hostname."""
        gen = HostnameGenerator(None)
        commands = gen.generate()

        assert len(commands) == 0


class TestSshKeyGenerator:
    """Tests for SSH key configuration generator."""

    def test_generate_with_rsa_key(self):
        """Test SSH key generation with RSA key."""
        key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... user@host"
        gen = SshKeyGenerator(key)
        commands = gen.generate()

        assert len(commands) == 3
        assert commands[0] == "set service ssh port 22"
        # Key identifier is sanitized: @ -> _at_, . -> _
        assert (
            "set system login user vyos authentication public-keys "
            "user_at_host key AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."
        ) in commands[1]
        assert (
            "set system login user vyos authentication public-keys user_at_host type ssh-rsa"
        ) in commands[2]

    def test_generate_with_ed25519_key(self):
        """Test SSH key generation with ED25519 key."""
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... admin@example.com"
        gen = SshKeyGenerator(key)
        commands = gen.generate()

        assert len(commands) == 3
        assert commands[0] == "set service ssh port 22"
        # Key identifier is sanitized: @ -> _at_, . -> _
        assert (
            "set system login user vyos authentication public-keys "
            "admin_at_example_com key AAAAC3NzaC1lZDI1NTE5AAAAI..."
        ) in commands[1]
        assert (
            "set system login user vyos authentication public-keys "
            "admin_at_example_com type ssh-ed25519"
        ) in commands[2]

    def test_generate_without_comment(self):
        """Test SSH key generation without comment (uses 'key1' as default)."""
        key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."
        gen = SshKeyGenerator(key)
        commands = gen.generate()

        assert len(commands) == 3
        assert commands[0] == "set service ssh port 22"
        assert (
            "set system login user vyos authentication public-keys "
            "key1 key AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."
        ) in commands[1]
        assert (
            "set system login user vyos authentication public-keys key1 type ssh-rsa"
        ) in commands[2]

    def test_generate_with_spaces_in_comment(self):
        """Test SSH key generation with spaces in comment (replaces with underscores)."""
        key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... John Doe"
        gen = SshKeyGenerator(key)
        commands = gen.generate()

        assert len(commands) == 3
        assert commands[0] == "set service ssh port 22"
        assert "John_Doe" in commands[1]
        assert "John_Doe" in commands[2]

    def test_generate_with_none(self):
        """Test SSH key generation with None."""
        gen = SshKeyGenerator(None)
        commands = gen.generate()

        assert len(commands) == 0

    def test_generate_with_invalid_key(self):
        """Test SSH key generation with invalid key format (too few parts)."""
        key = "invalid-key"
        gen = SshKeyGenerator(key)
        commands = gen.generate()

        assert len(commands) == 0


class TestInterfaceGenerator:
    """Tests for interface configuration generator."""

    def test_generate_single_interface(self):
        """Test interface generation with single interface."""
        iface = InterfaceConfig(
            name="eth0",
            ip=IPv4Address("10.0.1.1"),
            mask="255.255.255.0",
        )
        gen = InterfaceGenerator([iface], [])
        commands = gen.generate()

        assert len(commands) == 1
        assert "set interfaces ethernet eth0 address 10.0.1.1/24" in commands

    def test_generate_multiple_interfaces(self):
        """Test interface generation with multiple interfaces."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.1.1"),
                mask="255.255.255.0",
            ),
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.255.0",
            ),
        ]
        gen = InterfaceGenerator(interfaces, [])
        commands = gen.generate()

        assert len(commands) == 2
        assert "set interfaces ethernet eth0 address 10.0.1.1/24" in commands
        assert "set interfaces ethernet eth1 address 192.168.1.1/24" in commands

    def test_generate_with_mtu(self):
        """Test interface generation with MTU specified."""
        iface = InterfaceConfig(
            name="eth0",
            ip=IPv4Address("10.0.1.1"),
            mask="255.255.255.0",
            mtu=9000,
        )
        gen = InterfaceGenerator([iface], [])
        commands = gen.generate()

        assert len(commands) == 2
        assert "set interfaces ethernet eth0 address 10.0.1.1/24" in commands
        assert "set interfaces ethernet eth0 mtu 9000" in commands

    def test_generate_with_alias(self):
        """Test interface generation with alias (secondary IP)."""
        iface = InterfaceConfig(
            name="eth0",
            ip=IPv4Address("10.0.1.1"),
            mask="255.255.255.0",
        )
        alias = AliasConfig(
            interface="eth0",
            ip=IPv4Address("10.0.1.2"),
            mask="255.255.255.0",
        )
        gen = InterfaceGenerator([iface], [alias])
        commands = gen.generate()

        assert len(commands) == 2
        assert "set interfaces ethernet eth0 address 10.0.1.1/24" in commands
        assert "set interfaces ethernet eth0 address 10.0.1.2/24" in commands

    def test_generate_with_alias_no_mask(self):
        """Test interface generation with alias missing mask (uses parent mask)."""
        iface = InterfaceConfig(
            name="eth0",
            ip=IPv4Address("129.244.246.64"),
            mask="255.255.255.0",
        )
        alias = AliasConfig(
            interface="eth0",
            ip=IPv4Address("129.244.246.66"),
            mask=None,  # Missing mask (OpenNebula bug)
        )
        gen = InterfaceGenerator([iface], [alias])
        commands = gen.generate()

        assert len(commands) == 2
        assert "set interfaces ethernet eth0 address 129.244.246.64/24" in commands
        assert "set interfaces ethernet eth0 address 129.244.246.66/24" in commands

    def test_generate_with_multiple_aliases(self):
        """Test interface generation with multiple aliases on same interface."""
        iface = InterfaceConfig(
            name="eth0",
            ip=IPv4Address("10.0.1.1"),
            mask="255.255.255.0",
        )
        aliases = [
            AliasConfig(
                interface="eth0",
                ip=IPv4Address("10.0.1.2"),
                mask="255.255.255.0",
            ),
            AliasConfig(
                interface="eth0",
                ip=IPv4Address("10.0.1.3"),
                mask="255.255.255.0",
            ),
        ]
        gen = InterfaceGenerator([iface], aliases)
        commands = gen.generate()

        assert len(commands) == 3
        assert "set interfaces ethernet eth0 address 10.0.1.1/24" in commands
        assert "set interfaces ethernet eth0 address 10.0.1.2/24" in commands
        assert "set interfaces ethernet eth0 address 10.0.1.3/24" in commands

    def test_generate_different_subnet_masks(self):
        """Test interface generation with different subnet masks."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.1.1"),
                mask="255.255.255.0",  # /24
            ),
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.0.0",  # /16
            ),
        ]
        gen = InterfaceGenerator(interfaces, [])
        commands = gen.generate()

        assert len(commands) == 2
        assert "set interfaces ethernet eth0 address 10.0.1.1/24" in commands
        assert "set interfaces ethernet eth1 address 192.168.1.1/16" in commands

    def test_generate_empty_config(self):
        """Test interface generation with no interfaces."""
        gen = InterfaceGenerator([], [])
        commands = gen.generate()

        assert len(commands) == 0


class TestRoutingGenerator:
    """Tests for routing configuration generator."""

    def test_generate_default_gateway_simple(self):
        """Test default gateway generation with single valid gateway."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.254"),
            )
        ]
        gen = RoutingGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 1
        assert commands[0] == "set protocols static route 0.0.0.0/0 next-hop 10.0.0.254"

    def test_generate_gateway_equals_interface_ip_ignored(self):
        """Test that gateway is ignored when it equals the interface's own IP.

        This handles the case where the router IS the gateway for a network.
        """
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("192.168.1.1"),  # Gateway == interface IP
            )
        ]
        gen = RoutingGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 0  # No default route generated

    def test_generate_management_vrf_interface_excluded(self):
        """Test that management VRF interfaces are excluded from default gateway selection."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.254"),
                management=True,  # Management VRF
            )
        ]
        gen = RoutingGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 0  # No default route generated

    def test_generate_lowest_numbered_interface_wins(self):
        """Test that the lowest-numbered interface with valid gateway wins."""
        interfaces = [
            InterfaceConfig(
                name="eth2",
                ip=IPv4Address("172.16.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("172.16.0.254"),
            ),
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.254"),
            ),
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("192.168.1.254"),
            ),
        ]
        gen = RoutingGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 1
        # eth0 should win (lowest numbered with valid gateway)
        assert commands[0] == "set protocols static route 0.0.0.0/0 next-hop 10.0.0.254"

    def test_generate_natural_sorting_double_digit_interfaces(self):
        """Test that natural sorting correctly orders eth2 before eth10.

        This verifies the natural_sort_key function handles double-digit
        interface numbers correctly (numeric order, not lexicographic).
        """
        interfaces = [
            InterfaceConfig(
                name="eth10",
                ip=IPv4Address("10.10.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.10.0.254"),
            ),
            InterfaceConfig(
                name="eth2",
                ip=IPv4Address("10.2.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.2.0.254"),
            ),
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.254"),
            ),
        ]
        gen = RoutingGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 1
        # eth0 should win (0 < 2 < 10 in numeric order)
        assert commands[0] == "set protocols static route 0.0.0.0/0 next-hop 10.0.0.254"

    def test_generate_skips_interface_without_gateway(self):
        """Test that interfaces without gateways are skipped."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                # No gateway
            ),
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("192.168.1.254"),
            ),
        ]
        gen = RoutingGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 1
        # eth1 should win (eth0 has no gateway)
        assert commands[0] == "set protocols static route 0.0.0.0/0 next-hop 192.168.1.254"

    def test_generate_complex_scenario(self):
        """Test complex scenario with multiple exclusion conditions.

        eth0: 10.0.0.1/24, gateway 10.0.0.254 -> wins (gateway != interface IP)
        eth1: 192.168.1.1/24, gateway 192.168.1.1 -> ignored (router IS the gateway)
        eth2: 172.16.0.1/24, no gateway -> ignored
        eth3: 10.1.0.1/24, gateway 10.1.0.254, management=True -> ignored (management VRF)
        """
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.254"),
            ),
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("192.168.1.1"),  # Router IS gateway
            ),
            InterfaceConfig(
                name="eth2",
                ip=IPv4Address("172.16.0.1"),
                mask="255.255.255.0",
                # No gateway
            ),
            InterfaceConfig(
                name="eth3",
                ip=IPv4Address("10.1.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.1.0.254"),
                management=True,  # Management VRF
            ),
        ]
        gen = RoutingGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 1
        assert commands[0] == "set protocols static route 0.0.0.0/0 next-hop 10.0.0.254"

    def test_generate_no_valid_gateway(self):
        """Test scenario where no interface has a valid gateway."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                # No gateway
            ),
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("192.168.1.1"),  # Router IS gateway
            ),
        ]
        gen = RoutingGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 0

    def test_generate_empty_interfaces(self):
        """Test routing generation with no interfaces."""
        gen = RoutingGenerator([])
        commands = gen.generate()

        assert len(commands) == 0

    def test_generate_fallback_to_later_interface(self):
        """Test that later interface is used when earlier interfaces are invalid."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.1"),  # Gateway == interface (invalid)
            ),
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("192.168.1.254"),  # Valid gateway
            ),
        ]
        gen = RoutingGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 1
        # eth1 should win (eth0's gateway equals its own IP)
        assert commands[0] == "set protocols static route 0.0.0.0/0 next-hop 192.168.1.254"

    def test_generate_all_interfaces_management_vrf(self):
        """Test that no default gateway is generated when all interfaces are management VRF."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.254"),
                management=True,
            ),
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("192.168.1.254"),
                management=True,
            ),
        ]
        gen = RoutingGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 0


class TestStaticRoutesGenerator:
    """Tests for static routes configuration generator."""

    def test_generate_no_routes_config(self):
        """Test generation with no routes configured (None)."""
        from vyos_onecontext.generators.routing import StaticRoutesGenerator

        gen = StaticRoutesGenerator(None)
        commands = gen.generate()

        assert len(commands) == 0

    def test_generate_empty_routes_list(self):
        """Test generation with empty routes list."""
        from vyos_onecontext.generators.routing import StaticRoutesGenerator
        from vyos_onecontext.models.routing import RoutesConfig

        routes = RoutesConfig(static=[])
        gen = StaticRoutesGenerator(routes)
        commands = gen.generate()

        assert len(commands) == 0

    def test_generate_simple_gateway_route(self):
        """Test simple static route with next-hop gateway."""
        from vyos_onecontext.generators.routing import StaticRoutesGenerator
        from vyos_onecontext.models.routing import RoutesConfig, StaticRoute

        routes = RoutesConfig(
            static=[
                StaticRoute(
                    interface="eth1",
                    destination="10.96.0.0/13",
                    gateway="10.63.255.1",
                )
            ]
        )
        gen = StaticRoutesGenerator(routes)
        commands = gen.generate()

        assert len(commands) == 1
        assert commands[0] == "set protocols static route 10.96.0.0/13 next-hop 10.63.255.1"

    def test_generate_default_route_via_gateway(self):
        """Test default route (0.0.0.0/0) with gateway."""
        from vyos_onecontext.generators.routing import StaticRoutesGenerator
        from vyos_onecontext.models.routing import RoutesConfig, StaticRoute

        routes = RoutesConfig(
            static=[
                StaticRoute(
                    interface="eth0",
                    destination="0.0.0.0/0",
                    gateway="203.0.113.1",
                )
            ]
        )
        gen = StaticRoutesGenerator(routes)
        commands = gen.generate()

        assert len(commands) == 1
        assert commands[0] == "set protocols static route 0.0.0.0/0 next-hop 203.0.113.1"

    def test_generate_interface_route_no_gateway(self):
        """Test interface route (no next-hop gateway specified)."""
        from vyos_onecontext.generators.routing import StaticRoutesGenerator
        from vyos_onecontext.models.routing import RoutesConfig, StaticRoute

        routes = RoutesConfig(
            static=[
                StaticRoute(
                    interface="eth2",
                    destination="192.168.0.0/16",
                )
            ]
        )
        gen = StaticRoutesGenerator(routes)
        commands = gen.generate()

        assert len(commands) == 1
        assert commands[0] == "set protocols static route 192.168.0.0/16 interface eth2"

    def test_generate_route_with_custom_distance(self):
        """Test route with custom administrative distance."""
        from vyos_onecontext.generators.routing import StaticRoutesGenerator
        from vyos_onecontext.models.routing import RoutesConfig, StaticRoute

        routes = RoutesConfig(
            static=[
                StaticRoute(
                    interface="eth1",
                    destination="10.0.0.0/8",
                    gateway="10.63.255.1",
                    distance=10,
                )
            ]
        )
        gen = StaticRoutesGenerator(routes)
        commands = gen.generate()

        assert len(commands) == 1
        assert (
            commands[0] == "set protocols static route 10.0.0.0/8 next-hop 10.63.255.1 distance 10"
        )

    def test_generate_interface_route_with_distance(self):
        """Test interface route with custom administrative distance."""
        from vyos_onecontext.generators.routing import StaticRoutesGenerator
        from vyos_onecontext.models.routing import RoutesConfig, StaticRoute

        routes = RoutesConfig(
            static=[
                StaticRoute(
                    interface="eth2",
                    destination="192.168.0.0/16",
                    distance=5,
                )
            ]
        )
        gen = StaticRoutesGenerator(routes)
        commands = gen.generate()

        assert len(commands) == 1
        assert commands[0] == "set protocols static route 192.168.0.0/16 interface eth2 distance 5"

    def test_generate_route_with_vrf(self):
        """Test route assigned to a VRF."""
        from vyos_onecontext.generators.routing import StaticRoutesGenerator
        from vyos_onecontext.models.routing import RoutesConfig, StaticRoute

        routes = RoutesConfig(
            static=[
                StaticRoute(
                    interface="eth0",
                    destination="192.168.0.0/16",
                    gateway="10.0.1.254",
                    vrf="management",
                )
            ]
        )
        gen = StaticRoutesGenerator(routes)
        commands = gen.generate()

        assert len(commands) == 1
        assert (
            commands[0]
            == "set vrf name management protocols static route 192.168.0.0/16 next-hop 10.0.1.254"
        )

    def test_generate_vrf_route_with_distance(self):
        """Test VRF route with custom distance."""
        from vyos_onecontext.generators.routing import StaticRoutesGenerator
        from vyos_onecontext.models.routing import RoutesConfig, StaticRoute

        routes = RoutesConfig(
            static=[
                StaticRoute(
                    interface="eth0",
                    destination="192.168.0.0/16",
                    gateway="10.0.1.254",
                    vrf="management",
                    distance=20,
                )
            ]
        )
        gen = StaticRoutesGenerator(routes)
        commands = gen.generate()

        assert len(commands) == 1
        assert (
            commands[0] == "set vrf name management protocols static route 192.168.0.0/16 "
            "next-hop 10.0.1.254 distance 20"
        )

    def test_generate_multiple_routes(self):
        """Test generation with multiple static routes."""
        from vyos_onecontext.generators.routing import StaticRoutesGenerator
        from vyos_onecontext.models.routing import RoutesConfig, StaticRoute

        routes = RoutesConfig(
            static=[
                StaticRoute(
                    interface="eth1",
                    destination="0.0.0.0/0",
                    gateway="10.63.255.1",
                ),
                StaticRoute(
                    interface="eth2",
                    destination="10.96.0.0/13",
                    gateway="10.69.100.1",
                ),
                StaticRoute(
                    interface="eth3",
                    destination="192.168.0.0/16",
                ),
            ]
        )
        gen = StaticRoutesGenerator(routes)
        commands = gen.generate()

        assert len(commands) == 3
        assert "set protocols static route 0.0.0.0/0 next-hop 10.63.255.1" in commands
        assert "set protocols static route 10.96.0.0/13 next-hop 10.69.100.1" in commands
        assert "set protocols static route 192.168.0.0/16 interface eth3" in commands

    def test_generate_mixed_vrf_and_main_routes(self):
        """Test generation with routes in both main routing table and VRF."""
        from vyos_onecontext.generators.routing import StaticRoutesGenerator
        from vyos_onecontext.models.routing import RoutesConfig, StaticRoute

        routes = RoutesConfig(
            static=[
                StaticRoute(
                    interface="eth1",
                    destination="0.0.0.0/0",
                    gateway="10.63.255.1",
                ),
                StaticRoute(
                    interface="eth0",
                    destination="192.168.0.0/16",
                    gateway="10.0.1.254",
                    vrf="management",
                ),
            ]
        )
        gen = StaticRoutesGenerator(routes)
        commands = gen.generate()

        assert len(commands) == 2
        assert "set protocols static route 0.0.0.0/0 next-hop 10.63.255.1" in commands
        assert (
            "set vrf name management protocols static route 192.168.0.0/16 next-hop 10.0.1.254"
            in commands
        )

    def test_generate_route_default_distance_not_included(self):
        """Test that default distance (1) is not explicitly set in commands."""
        from vyos_onecontext.generators.routing import StaticRoutesGenerator
        from vyos_onecontext.models.routing import RoutesConfig, StaticRoute

        routes = RoutesConfig(
            static=[
                StaticRoute(
                    interface="eth1",
                    destination="10.0.0.0/8",
                    gateway="10.63.255.1",
                    distance=1,  # Default distance
                )
            ]
        )
        gen = StaticRoutesGenerator(routes)
        commands = gen.generate()

        # Should only have the base next-hop command, not the distance command
        assert len(commands) == 1
        assert commands[0] == "set protocols static route 10.0.0.0/8 next-hop 10.63.255.1"

    def test_generate_vrf_interface_route_no_gateway(self):
        """Test VRF interface route without gateway."""
        from vyos_onecontext.generators.routing import StaticRoutesGenerator
        from vyos_onecontext.models.routing import RoutesConfig, StaticRoute

        routes = RoutesConfig(
            static=[
                StaticRoute(
                    interface="eth0",
                    destination="192.168.0.0/16",
                    vrf="management",
                )
            ]
        )
        gen = StaticRoutesGenerator(routes)
        commands = gen.generate()

        assert len(commands) == 1
        assert (
            commands[0]
            == "set vrf name management protocols static route 192.168.0.0/16 interface eth0"
        )

    def test_generate_vrf_interface_route_with_distance(self):
        """Test VRF interface route with custom administrative distance."""
        from vyos_onecontext.generators.routing import StaticRoutesGenerator
        from vyos_onecontext.models.routing import RoutesConfig, StaticRoute

        routes = RoutesConfig(
            static=[
                StaticRoute(
                    interface="eth0",
                    destination="192.168.0.0/16",
                    vrf="management",
                    distance=5,
                )
            ]
        )
        gen = StaticRoutesGenerator(routes)
        commands = gen.generate()

        assert len(commands) == 1
        assert (
            commands[0] == "set vrf name management protocols static route 192.168.0.0/16 "
            "interface eth0 distance 5"
        )


class TestGenerateConfig:
    """Tests for top-level generate_config function."""

    def test_generate_minimal_config(self):
        """Test config generation with minimal configuration."""
        config = RouterConfig(
            hostname="router-01",
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                )
            ],
        )
        commands = generate_config(config)

        # Should have hostname + interface
        assert len(commands) == 2
        assert "set system host-name router-01" in commands
        assert "set interfaces ethernet eth0 address 10.0.1.1/24" in commands

    def test_generate_full_system_config(self):
        """Test config generation with all system features."""
        config = RouterConfig(
            hostname="router-01",
            ssh_public_key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+test user@host",
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                    mtu=9000,
                ),
                InterfaceConfig(
                    name="eth1",
                    ip=IPv4Address("192.168.1.1"),
                    mask="255.255.255.0",
                ),
            ],
            aliases=[
                AliasConfig(
                    interface="eth0",
                    ip=IPv4Address("10.0.1.2"),
                    mask="255.255.255.0",
                )
            ],
        )
        commands = generate_config(config)

        # Should have: hostname + 3 SSH commands (service enable + 2 key commands)
        # + 3 interface commands (2 primary + 1 MTU) + 1 alias
        assert len(commands) == 8
        assert "set system host-name router-01" in commands
        assert any("public-keys" in cmd for cmd in commands)
        assert "set interfaces ethernet eth0 address 10.0.1.1/24" in commands
        assert "set interfaces ethernet eth0 mtu 9000" in commands
        assert "set interfaces ethernet eth1 address 192.168.1.1/24" in commands
        assert "set interfaces ethernet eth0 address 10.0.1.2/24" in commands

    def test_generate_no_optional_config(self):
        """Test config generation with no optional features."""
        config = RouterConfig(
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                )
            ]
        )
        commands = generate_config(config)

        # Should only have interface command
        assert len(commands) == 1
        assert "set interfaces ethernet eth0 address 10.0.1.1/24" in commands

    def test_command_order(self):
        """Test that commands are generated in correct order (system, then interfaces)."""
        config = RouterConfig(
            hostname="router-01",
            ssh_public_key="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+test user@host",
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                )
            ],
        )
        commands = generate_config(config)

        # Find indices of different command types
        hostname_idx = next(i for i, cmd in enumerate(commands) if "host-name" in cmd)
        ssh_key_idx = next(i for i, cmd in enumerate(commands) if "public-keys" in cmd)
        interface_idx = next(i for i, cmd in enumerate(commands) if "interfaces ethernet" in cmd)

        # System commands should come before interface commands
        assert hostname_idx < interface_idx
        assert ssh_key_idx < interface_idx

    def test_generate_config_with_default_gateway(self):
        """Test config generation includes default gateway when interface has valid gateway."""
        config = RouterConfig(
            hostname="router-01",
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                    gateway=IPv4Address("10.0.1.254"),
                )
            ],
        )
        commands = generate_config(config)

        # Should have hostname + interface + default route
        assert len(commands) == 3
        assert "set system host-name router-01" in commands
        assert "set interfaces ethernet eth0 address 10.0.1.1/24" in commands
        assert "set protocols static route 0.0.0.0/0 next-hop 10.0.1.254" in commands

    def test_generate_config_gateway_equals_interface_ip_no_route(self):
        """Test config generation skips default gateway when gateway equals interface IP."""
        config = RouterConfig(
            hostname="router-01",
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                    gateway=IPv4Address("10.0.1.1"),  # Gateway == interface IP
                )
            ],
        )
        commands = generate_config(config)

        # Should only have hostname + interface (no default route)
        assert len(commands) == 2
        assert "set system host-name router-01" in commands
        assert "set interfaces ethernet eth0 address 10.0.1.1/24" in commands
        assert not any("0.0.0.0/0" in cmd for cmd in commands)

    def test_generate_config_command_order_with_routing(self):
        """Test that routing commands come after interface commands."""
        config = RouterConfig(
            hostname="router-01",
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                    gateway=IPv4Address("10.0.1.254"),
                )
            ],
        )
        commands = generate_config(config)

        # Find indices of different command types
        hostname_idx = next(i for i, cmd in enumerate(commands) if "host-name" in cmd)
        interface_idx = next(i for i, cmd in enumerate(commands) if "interfaces ethernet" in cmd)
        routing_idx = next(i for i, cmd in enumerate(commands) if "protocols static" in cmd)

        # System -> Interfaces -> Routing
        assert hostname_idx < interface_idx
        assert interface_idx < routing_idx


class TestSshServiceGenerator:
    """Tests for SSH service configuration generator."""

    def test_no_management_vrf(self):
        """No SSH VRF binding when no management interfaces."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.254"),
            )
        ]
        gen = SshServiceGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 0

    def test_ssh_bound_to_management_vrf(self):
        """SSH bound to management VRF when management interface exists."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.254"),
                management=True,
            )
        ]
        gen = SshServiceGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 1
        assert commands[0] == "set service ssh vrf management"

    def test_ssh_bound_with_multiple_management_interfaces(self):
        """SSH bound to management VRF when multiple management interfaces exist."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.254"),
                management=True,
            ),
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("192.168.1.254"),
                management=True,
            ),
        ]
        gen = SshServiceGenerator(interfaces)
        commands = gen.generate()

        # Only one SSH VRF binding command regardless of number of management interfaces
        assert len(commands) == 1
        assert commands[0] == "set service ssh vrf management"

    def test_ssh_bound_with_mixed_interfaces(self):
        """SSH bound to management VRF when mix of management and non-management interfaces."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.254"),
                management=False,
            ),
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("192.168.1.254"),
                management=True,
            ),
        ]
        gen = SshServiceGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 1
        assert commands[0] == "set service ssh vrf management"

    def test_empty_interfaces(self):
        """No SSH VRF binding with empty interface list."""
        gen = SshServiceGenerator([])
        commands = gen.generate()

        assert len(commands) == 0


class TestVrfGenerator:
    """Tests for VRF configuration generator."""

    def test_constants_exported(self):
        """Test that VRF constants are exported correctly."""
        assert VRF_NAME == "management"
        assert VRF_TABLE_ID == 100

    def test_generate_no_management_interfaces(self):
        """Test VRF generation with no management interfaces."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.254"),
            )
        ]
        gen = VrfGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 0

    def test_generate_single_management_interface(self):
        """Test VRF generation with single management interface."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.254"),
                management=True,
            )
        ]
        gen = VrfGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 3
        assert commands[0] == "set vrf name management table 100"
        assert commands[1] == "set interfaces ethernet eth0 vrf management"
        assert commands[2] == (
            "set vrf name management protocols static route 0.0.0.0/0 next-hop 10.0.0.254"
        )

    def test_generate_multiple_management_interfaces(self):
        """Test VRF generation with multiple management interfaces."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.254"),
                management=True,
            ),
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("192.168.1.254"),
                management=True,
            ),
        ]
        gen = VrfGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 4
        assert commands[0] == "set vrf name management table 100"
        assert "set interfaces ethernet eth0 vrf management" in commands
        assert "set interfaces ethernet eth1 vrf management" in commands
        # eth0 should provide the gateway (lowest numbered)
        assert commands[3] == (
            "set vrf name management protocols static route 0.0.0.0/0 next-hop 10.0.0.254"
        )

    def test_generate_mixed_management_and_non_management(self):
        """Test VRF generation with mixed interface types."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.254"),
                management=False,
            ),
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("192.168.1.254"),
                management=True,
            ),
        ]
        gen = VrfGenerator(interfaces)
        commands = gen.generate()

        assert len(commands) == 3
        assert commands[0] == "set vrf name management table 100"
        # Only eth1 should be in management VRF
        assert commands[1] == "set interfaces ethernet eth1 vrf management"
        assert commands[2] == (
            "set vrf name management protocols static route 0.0.0.0/0 next-hop 192.168.1.254"
        )

    def test_generate_management_interface_no_gateway(self):
        """Test VRF generation with management interface without gateway."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                management=True,
                # No gateway
            )
        ]
        gen = VrfGenerator(interfaces)
        commands = gen.generate()

        # Should have VRF creation and interface assignment, but no route
        assert len(commands) == 2
        assert commands[0] == "set vrf name management table 100"
        assert commands[1] == "set interfaces ethernet eth0 vrf management"

    def test_generate_management_interface_gateway_equals_ip(self):
        """Test VRF generation when gateway equals interface IP."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.1"),  # Gateway == interface IP
                management=True,
            )
        ]
        gen = VrfGenerator(interfaces)
        commands = gen.generate()

        # Should have VRF creation and interface assignment, but no route
        assert len(commands) == 2
        assert commands[0] == "set vrf name management table 100"
        assert commands[1] == "set interfaces ethernet eth0 vrf management"

    def test_generate_gateway_selection_lowest_numbered_wins(self):
        """Test VRF gateway selection picks lowest numbered interface."""
        interfaces = [
            InterfaceConfig(
                name="eth2",
                ip=IPv4Address("172.16.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("172.16.0.254"),
                management=True,
            ),
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.254"),
                management=True,
            ),
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("192.168.1.254"),
                management=True,
            ),
        ]
        gen = VrfGenerator(interfaces)
        commands = gen.generate()

        # eth0 should provide the gateway (lowest numbered)
        assert commands[-1] == (
            "set vrf name management protocols static route 0.0.0.0/0 next-hop 10.0.0.254"
        )

    def test_generate_gateway_selection_natural_sorting(self):
        """Test VRF gateway selection uses natural sorting (eth2 before eth10)."""
        interfaces = [
            InterfaceConfig(
                name="eth10",
                ip=IPv4Address("10.10.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.10.0.254"),
                management=True,
            ),
            InterfaceConfig(
                name="eth2",
                ip=IPv4Address("10.2.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.2.0.254"),
                management=True,
            ),
        ]
        gen = VrfGenerator(interfaces)
        commands = gen.generate()

        # eth2 should provide the gateway (2 < 10 numerically)
        assert commands[-1] == (
            "set vrf name management protocols static route 0.0.0.0/0 next-hop 10.2.0.254"
        )

    def test_generate_gateway_fallback_to_later_interface(self):
        """Test VRF gateway selection falls back when first interface is invalid."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.0.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("10.0.0.1"),  # Gateway == IP (invalid)
                management=True,
            ),
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.255.0",
                gateway=IPv4Address("192.168.1.254"),  # Valid
                management=True,
            ),
        ]
        gen = VrfGenerator(interfaces)
        commands = gen.generate()

        # eth1 should provide the gateway since eth0's is invalid
        assert commands[-1] == (
            "set vrf name management protocols static route 0.0.0.0/0 next-hop 192.168.1.254"
        )

    def test_generate_empty_interfaces(self):
        """Test VRF generation with empty interface list."""
        gen = VrfGenerator([])
        commands = gen.generate()

        assert len(commands) == 0


class TestGenerateConfigWithVrf:
    """Tests for generate_config function with VRF support."""

    def test_generate_config_with_management_interface(self):
        """Test config generation includes VRF commands for management interfaces."""
        config = RouterConfig(
            hostname="router-01",
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                    gateway=IPv4Address("10.0.1.254"),
                ),
                InterfaceConfig(
                    name="eth1",
                    ip=IPv4Address("192.168.1.1"),
                    mask="255.255.255.0",
                    gateway=IPv4Address("192.168.1.254"),
                    management=True,
                ),
            ],
        )
        commands = generate_config(config)

        # Should have: hostname + 2 interfaces + default route + VRF (3 commands) + SSH VRF
        assert "set system host-name router-01" in commands
        assert "set interfaces ethernet eth0 address 10.0.1.1/24" in commands
        assert "set interfaces ethernet eth1 address 192.168.1.1/24" in commands
        # Default route from non-management interface
        assert "set protocols static route 0.0.0.0/0 next-hop 10.0.1.254" in commands
        # VRF commands
        assert "set vrf name management table 100" in commands
        assert "set interfaces ethernet eth1 vrf management" in commands
        assert (
            "set vrf name management protocols static route 0.0.0.0/0 next-hop 192.168.1.254"
        ) in commands
        # SSH VRF binding
        assert "set service ssh vrf management" in commands

    def test_generate_config_no_management_interface(self):
        """Test config generation has no VRF commands without management interfaces."""
        config = RouterConfig(
            hostname="router-01",
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                    gateway=IPv4Address("10.0.1.254"),
                ),
            ],
        )
        commands = generate_config(config)

        # Should NOT have any VRF commands
        assert not any("vrf" in cmd for cmd in commands)

    def test_generate_config_command_order_with_vrf(self):
        """Test that VRF commands come after routing commands, SSH VRF after VRF."""
        config = RouterConfig(
            hostname="router-01",
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                    gateway=IPv4Address("10.0.1.254"),
                ),
                InterfaceConfig(
                    name="eth1",
                    ip=IPv4Address("192.168.1.1"),
                    mask="255.255.255.0",
                    gateway=IPv4Address("192.168.1.254"),
                    management=True,
                ),
            ],
        )
        commands = generate_config(config)

        # Find indices of different command types
        interface_idx = next(
            i
            for i, cmd in enumerate(commands)
            if "interfaces ethernet" in cmd and " address " in cmd
        )
        routing_idx = next(
            i for i, cmd in enumerate(commands) if cmd.startswith("set protocols static")
        )
        vrf_idx = next(i for i, cmd in enumerate(commands) if "vrf name" in cmd)
        ssh_vrf_idx = next(i for i, cmd in enumerate(commands) if "service ssh vrf" in cmd)

        # Interfaces -> Routing -> VRF -> SSH VRF
        assert interface_idx < routing_idx
        assert routing_idx < vrf_idx
        assert vrf_idx < ssh_vrf_idx

    def test_generate_config_static_routes_with_management_vrf(self):
        """Test that static routes referencing management VRF work correctly.

        This verifies that:
        1. Management VRF is created before static routes
        2. Routes can reference the management VRF
        3. Command ordering is: interfaces -> default routing -> VRF -> static routes -> SSH
        """
        from vyos_onecontext.models.routing import RoutesConfig, StaticRoute

        config = RouterConfig(
            hostname="router-01",
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                    gateway=IPv4Address("10.0.1.254"),
                ),
                InterfaceConfig(
                    name="eth1",
                    ip=IPv4Address("192.168.1.1"),
                    mask="255.255.255.0",
                    gateway=IPv4Address("192.168.1.254"),
                    management=True,
                ),
            ],
            routes=RoutesConfig(
                static=[
                    StaticRoute(
                        interface="eth1",
                        destination="10.96.0.0/13",
                        gateway="192.168.1.100",
                        vrf="management",
                    )
                ]
            ),
        )
        commands = generate_config(config)

        # Verify VRF is created
        assert "set vrf name management table 100" in commands

        # Verify static route references the VRF
        assert (
            "set vrf name management protocols static route 10.96.0.0/13 next-hop 192.168.1.100"
            in commands
        )

        # Verify command ordering: VRF creation comes BEFORE static routes
        vrf_creation_idx = next(
            i for i, cmd in enumerate(commands) if cmd == "set vrf name management table 100"
        )
        static_route_idx = next(
            i
            for i, cmd in enumerate(commands)
            if cmd
            == "set vrf name management protocols static route 10.96.0.0/13 next-hop 192.168.1.100"
        )

        # VRF must be created before routes can reference it
        assert vrf_creation_idx < static_route_idx
class TestOspfGenerator:
    """Tests for OSPF configuration generator."""

    def test_ospf_disabled(self):
        """Test OSPF generator with None config."""
        gen = OspfGenerator(None)
        commands = gen.generate()

        assert len(commands) == 0

    def test_ospf_enabled_but_false(self):
        """Test OSPF generator with enabled=False."""
        ospf = OspfConfig(enabled=False)
        gen = OspfGenerator(ospf)
        commands = gen.generate()

        assert len(commands) == 0

    def test_ospf_minimal_config(self):
        """Test minimal OSPF configuration with single interface."""
        ospf = OspfConfig(
            enabled=True,
            interfaces=[
                OspfInterface(name="eth1", area="0.0.0.0"),
            ],
        )
        gen = OspfGenerator(ospf)
        commands = gen.generate()

        # Should only have interface area assignment
        assert len(commands) == 1
        assert "set protocols ospf interface eth1 area '0.0.0.0'" in commands

    def test_ospf_with_router_id(self):
        """Test OSPF configuration with explicit router ID."""
        ospf = OspfConfig(
            enabled=True,
            router_id=IPv4Address("10.64.0.1"),
            interfaces=[
                OspfInterface(name="eth1", area="0.0.0.0"),
            ],
        )
        gen = OspfGenerator(ospf)
        commands = gen.generate()

        assert "set protocols ospf parameters router-id '10.64.0.1'" in commands
        assert "set protocols ospf interface eth1 area '0.0.0.0'" in commands

    def test_ospf_passive_interface(self):
        """Test OSPF passive interface configuration."""
        ospf = OspfConfig(
            enabled=True,
            interfaces=[
                OspfInterface(name="eth1", area="0.0.0.0", passive=True),
            ],
        )
        gen = OspfGenerator(ospf)
        commands = gen.generate()

        assert "set protocols ospf interface eth1 area '0.0.0.0'" in commands
        assert "set protocols ospf interface eth1 passive" in commands

    def test_ospf_interface_cost(self):
        """Test OSPF interface cost override."""
        ospf = OspfConfig(
            enabled=True,
            interfaces=[
                OspfInterface(name="eth1", area="0.0.0.0", cost=100),
            ],
        )
        gen = OspfGenerator(ospf)
        commands = gen.generate()

        assert "set protocols ospf interface eth1 area '0.0.0.0'" in commands
        assert "set protocols ospf interface eth1 cost '100'" in commands

    def test_ospf_multiple_interfaces(self):
        """Test OSPF with multiple interfaces in different areas."""
        ospf = OspfConfig(
            enabled=True,
            router_id=IPv4Address("10.64.0.1"),
            interfaces=[
                OspfInterface(name="eth1", area="0.0.0.0"),
                OspfInterface(name="eth2", area="0.0.0.0", cost=100),
                OspfInterface(name="eth3", area="0.0.0.1", passive=True),
            ],
        )
        gen = OspfGenerator(ospf)
        commands = gen.generate()

        # Router ID
        assert "set protocols ospf parameters router-id '10.64.0.1'" in commands
        # Interface 1 - basic
        assert "set protocols ospf interface eth1 area '0.0.0.0'" in commands
        # Interface 2 - with cost
        assert "set protocols ospf interface eth2 area '0.0.0.0'" in commands
        assert "set protocols ospf interface eth2 cost '100'" in commands
        # Interface 3 - different area, passive
        assert "set protocols ospf interface eth3 area '0.0.0.1'" in commands
        assert "set protocols ospf interface eth3 passive" in commands

    def test_ospf_redistribute_connected(self):
        """Test OSPF redistribute connected routes."""
        ospf = OspfConfig(
            enabled=True,
            interfaces=[
                OspfInterface(name="eth1", area="0.0.0.0"),
            ],
            redistribute=["connected"],
        )
        gen = OspfGenerator(ospf)
        commands = gen.generate()

        assert "set protocols ospf redistribute connected" in commands

    def test_ospf_redistribute_static(self):
        """Test OSPF redistribute static routes."""
        ospf = OspfConfig(
            enabled=True,
            interfaces=[
                OspfInterface(name="eth1", area="0.0.0.0"),
            ],
            redistribute=["static"],
        )
        gen = OspfGenerator(ospf)
        commands = gen.generate()

        assert "set protocols ospf redistribute static" in commands

    def test_ospf_redistribute_multiple(self):
        """Test OSPF redistribute multiple protocols."""
        ospf = OspfConfig(
            enabled=True,
            interfaces=[
                OspfInterface(name="eth1", area="0.0.0.0"),
            ],
            redistribute=["connected", "static", "kernel"],
        )
        gen = OspfGenerator(ospf)
        commands = gen.generate()

        assert "set protocols ospf redistribute connected" in commands
        assert "set protocols ospf redistribute static" in commands
        assert "set protocols ospf redistribute kernel" in commands

    def test_ospf_default_information_originate(self):
        """Test OSPF default-information originate."""
        ospf = OspfConfig(
            enabled=True,
            interfaces=[
                OspfInterface(name="eth1", area="0.0.0.0"),
            ],
            default_information=OspfDefaultInformation(originate=True),
        )
        gen = OspfGenerator(ospf)
        commands = gen.generate()

        assert "set protocols ospf default-information originate" in commands
        # Should NOT have "always" flag
        assert not any("always" in cmd for cmd in commands)

    def test_ospf_default_information_originate_always(self):
        """Test OSPF default-information originate always."""
        ospf = OspfConfig(
            enabled=True,
            interfaces=[
                OspfInterface(name="eth1", area="0.0.0.0"),
            ],
            default_information=OspfDefaultInformation(originate=True, always=True),
        )
        gen = OspfGenerator(ospf)
        commands = gen.generate()

        assert "set protocols ospf default-information originate always" in commands

    def test_ospf_default_information_with_metric(self):
        """Test OSPF default-information with metric."""
        ospf = OspfConfig(
            enabled=True,
            interfaces=[
                OspfInterface(name="eth1", area="0.0.0.0"),
            ],
            default_information=OspfDefaultInformation(originate=True, always=True, metric=100),
        )
        gen = OspfGenerator(ospf)
        commands = gen.generate()

        assert "set protocols ospf default-information originate always" in commands
        assert "set protocols ospf default-information originate metric '100'" in commands

    def test_ospf_full_config(self):
        """Test comprehensive OSPF configuration with all features."""
        ospf = OspfConfig(
            enabled=True,
            router_id=IPv4Address("10.64.0.1"),
            interfaces=[
                OspfInterface(name="eth1", area="0.0.0.0"),
                OspfInterface(name="eth2", area="0.0.0.0", cost=100),
                OspfInterface(name="eth3", area="0.0.0.0", passive=True),
            ],
            redistribute=["connected", "static"],
            default_information=OspfDefaultInformation(originate=True, always=True, metric=100),
        )
        gen = OspfGenerator(ospf)
        commands = gen.generate()

        # Router ID
        assert "set protocols ospf parameters router-id '10.64.0.1'" in commands
        # Interfaces
        assert "set protocols ospf interface eth1 area '0.0.0.0'" in commands
        assert "set protocols ospf interface eth2 area '0.0.0.0'" in commands
        assert "set protocols ospf interface eth2 cost '100'" in commands
        assert "set protocols ospf interface eth3 area '0.0.0.0'" in commands
        assert "set protocols ospf interface eth3 passive" in commands
        # Redistribution
        assert "set protocols ospf redistribute connected" in commands
        assert "set protocols ospf redistribute static" in commands
        # Default information
        assert "set protocols ospf default-information originate always" in commands
        assert "set protocols ospf default-information originate metric '100'" in commands


class TestGenerateConfigWithOspf:
    """Tests for generate_config function with OSPF support."""

    def test_generate_config_with_ospf(self):
        """Test config generation includes OSPF commands."""
        config = RouterConfig(
            hostname="router-01",
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                ),
                InterfaceConfig(
                    name="eth1",
                    ip=IPv4Address("10.64.1.1"),
                    mask="255.255.255.0"),
            ],
            ospf=OspfConfig(
                enabled=True,
                router_id=IPv4Address("10.64.0.1"),
                interfaces=[
                    OspfInterface(name="eth1", area="0.0.0.0"),
                ],
                redistribute=["connected"],
            ),
        )
        commands = generate_config(config)

        # Should have OSPF commands
        assert "set protocols ospf parameters router-id '10.64.0.1'" in commands
        assert "set protocols ospf interface eth1 area '0.0.0.0'" in commands
        assert "set protocols ospf redistribute connected" in commands

    def test_generate_config_without_ospf(self):
        """Test config generation without OSPF has no OSPF commands."""
        config = RouterConfig(
            hostname="router-01",
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                ),
            ],
        )
        commands = generate_config(config)

        # Should NOT have any OSPF commands
        assert not any("ospf" in cmd for cmd in commands)

    def test_generate_config_command_order_with_ospf(self):
        """Test that OSPF commands come after SSH VRF configuration."""
        config = RouterConfig(
            hostname="router-01",
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                    gateway=IPv4Address("10.0.1.254"),
                    management=True,
                ),
                InterfaceConfig(
                    name="eth1",
                    ip=IPv4Address("10.64.1.1"),
                    mask="255.255.255.0"),
            ],
            ospf=OspfConfig(
                enabled=True,
                interfaces=[
                    OspfInterface(name="eth1", area="0.0.0.0"),
                ],
            ),
        )
        commands = generate_config(config)

        # Find indices of different command types
        interface_idx = next(
            i
            for i, cmd in enumerate(commands)
            if "interfaces ethernet" in cmd and " address " in cmd
        )
        ssh_vrf_idx = next(
            i for i, cmd in enumerate(commands) if "service ssh vrf" in cmd
        )
        ospf_idx = next(i for i, cmd in enumerate(commands) if "ospf" in cmd)

        # Interfaces -> ... -> SSH VRF -> OSPF
        assert interface_idx < ssh_vrf_idx
        assert ssh_vrf_idx < ospf_idx
