"""Tests for RelayGenerator.

This module tests the VRF-based relay configuration generator, verifying that
it produces correct VyOS commands for VRF creation, policy-based routing,
NAT (DNAT/SNAT), proxy-ARP, and VRF-scoped static routes.
"""

from ipaddress import IPv4Address

from vyos_onecontext.generators.relay import RelayGenerator
from vyos_onecontext.models.interface import InterfaceConfig
from vyos_onecontext.models.relay import PivotConfig, RelayConfig, RelayTarget


class TestRelayGenerator:
    """Tests for RelayGenerator command generation."""

    def test_generate_with_none_config(self):
        """Test generator returns empty list when relay config is None."""
        gen = RelayGenerator(None, [])
        commands = gen.generate()

        assert len(commands) == 0

    def test_generate_single_pivot_single_target(self):
        """Test relay config with one pivot and one target.

        This is the simplest relay configuration: single egress interface,
        single target network. Verifies all command types are generated.
        """
        interfaces = [
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("10.40.0.1"),
                mask="255.255.0.0",
                gateway=IPv4Address("10.40.0.254"),
            ),
            InterfaceConfig(
                name="eth2",
                ip=IPv4Address("192.168.100.1"),
                mask="255.255.255.0",
            ),
        ]

        relay = RelayConfig(
            ingress_interface="eth1",
            pivots=[
                PivotConfig(
                    egress_interface="eth2",
                    targets=[
                        RelayTarget(
                            relay_prefix="10.32.5.0/24",
                            target_prefix="192.168.144.0/24",
                            gateway=IPv4Address("192.168.100.1"),
                        )
                    ],
                )
            ],
        )

        gen = RelayGenerator(relay, interfaces)
        commands = gen.generate()

        # Expected commands (in order):
        # 1. VRF creation and interface binding (ingress + egress)
        assert "set vrf name relay_eth1 table 149" in commands
        assert "set interfaces ethernet eth1 vrf relay_eth1" in commands
        assert "set vrf name relay_eth2 table 150" in commands
        assert "set interfaces ethernet eth2 vrf relay_eth2" in commands

        # 2. Ingress VRF default route
        assert (
            "set vrf name relay_eth1 protocols static route 0.0.0.0/0 next-hop 10.40.0.254"
            in commands
        )

        # 3. Cross-VRF proxy-ARP routes
        assert (
            "set vrf name relay_eth1 protocols static route 10.32.5.0/24 "
            "interface eth2 vrf relay_eth2" in commands
        )

        # 4. Policy-based routing
        assert "set policy route relay-pbr rule 10 destination address 10.32.5.0/24" in commands
        assert "set policy route relay-pbr rule 10 set table 150" in commands
        assert "set policy route relay-pbr interface eth1" in commands

        # 5. Destination NAT
        assert "set nat destination rule 5000 inbound-interface name eth1" in commands
        assert "set nat destination rule 5000 destination address 10.32.5.0/24" in commands
        assert "set nat destination rule 5000 translation address 192.168.144.0/24" in commands

        # 6. Source NAT (masquerade)
        assert "set nat source rule 5000 outbound-interface name eth2" in commands
        assert "set nat source rule 5000 translation address masquerade" in commands

        # 7. Proxy-ARP
        assert "set interfaces ethernet eth1 ip enable-proxy-arp" in commands

        # 8. Static routes in egress VRF
        assert (
            "set vrf name relay_eth2 protocols static route 192.168.144.0/24 next-hop 192.168.100.1"
            in commands
        )

        # 9. Egress VRF default route (return path)
        assert (
            "set vrf name relay_eth2 protocols static route 0.0.0.0/0 "
            "next-hop 10.40.0.254 vrf relay_eth1" in commands
        )

    def test_generate_single_pivot_multiple_targets(self):
        """Test relay config with one pivot and multiple targets.

        Verifies that multiple targets on the same pivot share:
        - Same egress VRF (one VRF per pivot)
        - Same SNAT rule (one masquerade per pivot)
        But have separate:
        - PBR rules (one per target)
        - DNAT rules (one per target)
        - Static routes (one per target)
        Additionally verifies ingress VRF is created with default route.
        """
        interfaces = [
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("10.40.0.1"),
                mask="255.255.0.0",
                gateway=IPv4Address("10.40.0.254"),
            ),
            InterfaceConfig(
                name="eth2",
                ip=IPv4Address("192.168.100.1"),
                mask="255.255.255.0",
            ),
        ]

        relay = RelayConfig(
            ingress_interface="eth1",
            pivots=[
                PivotConfig(
                    egress_interface="eth2",
                    targets=[
                        RelayTarget(
                            relay_prefix="10.32.5.0/24",
                            target_prefix="192.168.144.0/24",
                            gateway=IPv4Address("192.168.100.1"),
                        ),
                        RelayTarget(
                            relay_prefix="10.33.5.0/24",
                            target_prefix="10.123.105.0/24",
                            gateway=IPv4Address("192.168.100.1"),
                        ),
                    ],
                )
            ],
        )

        gen = RelayGenerator(relay, interfaces)
        commands = gen.generate()

        # VRF: Ingress VRF + one egress VRF for both targets (same pivot)
        assert "set vrf name relay_eth1 table 149" in commands
        assert "set interfaces ethernet eth1 vrf relay_eth1" in commands
        vrf_commands = [cmd for cmd in commands if cmd.startswith("set vrf name relay_eth2")]
        # 1 VRF creation + 2 egress static routes + 1 egress default route
        assert len(vrf_commands) == 4

        # Ingress default route
        assert (
            "set vrf name relay_eth1 protocols static route 0.0.0.0/0 next-hop 10.40.0.254"
            in commands
        )

        # Cross-VRF proxy-ARP routes (in ingress VRF)
        proxy_arp_routes = [
            cmd for cmd in commands
            if "vrf name relay_eth1 protocols static route" in cmd
            and "interface eth2" in cmd
        ]
        assert len(proxy_arp_routes) == 2  # One per target
        assert any("10.32.5.0/24" in cmd for cmd in proxy_arp_routes)
        assert any("10.33.5.0/24" in cmd for cmd in proxy_arp_routes)

        # SNAT: Only one masquerade rule for both targets (same egress)
        snat_commands = [cmd for cmd in commands if cmd.startswith("set nat source rule")]
        assert len(snat_commands) == 2  # 1 rule with 2 commands (interface + masquerade)

        # PBR: Two rules (one per target)
        pbr_rule_10 = [cmd for cmd in commands if "rule 10 " in cmd]
        pbr_rule_20 = [cmd for cmd in commands if "rule 20 " in cmd]
        assert len(pbr_rule_10) == 2  # destination address + set table
        assert len(pbr_rule_20) == 2  # destination address + set table
        assert "10.32.5.0/24" in " ".join(pbr_rule_10)
        assert "10.33.5.0/24" in " ".join(pbr_rule_20)

        # DNAT: Two rules (one per target)
        dnat_5000 = [cmd for cmd in commands if "nat destination rule 5000" in cmd]
        dnat_5010 = [cmd for cmd in commands if "nat destination rule 5010" in cmd]
        assert len(dnat_5000) == 3  # inbound-interface + destination + translation
        assert len(dnat_5010) == 3
        assert "10.32.5.0/24" in " ".join(dnat_5000)
        assert "10.33.5.0/24" in " ".join(dnat_5010)

        # Proxy-ARP: Should be enabled on ingress interface
        assert "set interfaces ethernet eth1 ip enable-proxy-arp" in commands

        # VRF static routes: Ingress default + proxy-ARP routes + egress routes + egress default
        vrf_static_routes = [
            cmd for cmd in commands if "vrf name" in cmd and "protocols static route" in cmd
        ]
        # 1 ingress default + 2 proxy-ARP routes + 2 egress routes + 1 egress default
        assert len(vrf_static_routes) == 6
        assert any("192.168.144.0/24" in cmd for cmd in vrf_static_routes)
        assert any("10.123.105.0/24" in cmd for cmd in vrf_static_routes)

        # Egress VRF default route (return path)
        assert (
            "set vrf name relay_eth2 protocols static route 0.0.0.0/0 "
            "next-hop 10.40.0.254 vrf relay_eth1" in commands
        )

    def test_generate_multiple_pivots_multiple_targets(self):
        """Test relay config with multiple pivots and multiple targets.

        This is the full-featured scenario: multiple egress interfaces,
        each with multiple targets. Verifies:
        - Ingress VRF table ID is 149
        - Egress VRF table IDs are sequential (150, 151, ...)
        - PBR rules are sequential across all targets (10, 20, 30, 40)
        - DNAT rules are sequential across all targets (5000, 5010, 5020, 5030)
        - SNAT rules are per-pivot, not per-target
        """
        relay = RelayConfig(
            ingress_interface="eth1",
            pivots=[
                PivotConfig(
                    egress_interface="eth2",
                    targets=[
                        RelayTarget(
                            relay_prefix="10.32.5.0/24",
                            target_prefix="192.168.144.0/24",
                            gateway=IPv4Address("192.168.100.1"),
                        ),
                        RelayTarget(
                            relay_prefix="10.33.5.0/24",
                            target_prefix="10.123.105.0/24",
                            gateway=IPv4Address("192.168.100.1"),
                        ),
                    ],
                ),
                PivotConfig(
                    egress_interface="eth3",
                    targets=[
                        RelayTarget(
                            relay_prefix="10.36.5.0/24",
                            target_prefix="10.101.105.0/24",
                            gateway=IPv4Address("10.101.105.1"),
                        ),
                        RelayTarget(
                            relay_prefix="10.36.105.0/25",
                            target_prefix="10.127.105.0/25",
                            gateway=IPv4Address("10.127.105.1"),
                        ),
                    ],
                ),
            ],
        )

        gen = RelayGenerator(relay)
        commands = gen.generate()

        # VRF creation: Ingress VRF + two egress VRFs with sequential table IDs
        assert "set vrf name relay_eth1 table 149" in commands
        assert "set interfaces ethernet eth1 vrf relay_eth1" in commands
        assert "set vrf name relay_eth2 table 150" in commands
        assert "set vrf name relay_eth3 table 151" in commands
        assert "set interfaces ethernet eth2 vrf relay_eth2" in commands
        assert "set interfaces ethernet eth3 vrf relay_eth3" in commands

        # PBR: Four rules (one per target) with correct table routing
        assert "set policy route relay-pbr rule 10 destination address 10.32.5.0/24" in commands
        assert "set policy route relay-pbr rule 10 set table 150" in commands
        assert "set policy route relay-pbr rule 20 destination address 10.33.5.0/24" in commands
        assert "set policy route relay-pbr rule 20 set table 150" in commands
        assert "set policy route relay-pbr rule 30 destination address 10.36.5.0/24" in commands
        assert "set policy route relay-pbr rule 30 set table 151" in commands
        assert "set policy route relay-pbr rule 40 destination address 10.36.105.0/25" in commands
        assert "set policy route relay-pbr rule 40 set table 151" in commands

        # DNAT: Four rules (one per target) with sequential numbering
        dnat_rules = [cmd for cmd in commands if cmd.startswith("set nat destination rule")]
        assert any("rule 5000 " in cmd for cmd in dnat_rules)
        assert any("rule 5010 " in cmd for cmd in dnat_rules)
        assert any("rule 5020 " in cmd for cmd in dnat_rules)
        assert any("rule 5030 " in cmd for cmd in dnat_rules)

        # SNAT: Two rules (one per pivot) with sequential numbering
        snat_rules = [cmd for cmd in commands if cmd.startswith("set nat source rule")]
        assert any("rule 5000 outbound-interface name eth2" in cmd for cmd in snat_rules)
        assert any("rule 5010 outbound-interface name eth3" in cmd for cmd in snat_rules)

        # Proxy-ARP: Should be enabled on ingress interface
        assert "set interfaces ethernet eth1 ip enable-proxy-arp" in commands

        # Cross-VRF proxy-ARP routes: Four routes in ingress VRF (one per target)
        ingress_vrf_routes = [
            cmd
            for cmd in commands
            if "vrf name relay_eth1 protocols static route" in cmd and "interface eth" in cmd
        ]
        assert len(ingress_vrf_routes) == 4
        assert any(
            "10.32.5.0/24 interface eth2 vrf relay_eth2" in cmd for cmd in ingress_vrf_routes
        )
        assert any(
            "10.33.5.0/24 interface eth2 vrf relay_eth2" in cmd for cmd in ingress_vrf_routes
        )
        assert any(
            "10.36.5.0/24 interface eth3 vrf relay_eth3" in cmd for cmd in ingress_vrf_routes
        )
        assert any(
            "10.36.105.0/25 interface eth3 vrf relay_eth3" in cmd for cmd in ingress_vrf_routes
        )

        # Egress VRF static routes: Four routes in correct VRFs
        assert (
            "set vrf name relay_eth2 protocols static route 192.168.144.0/24 next-hop 192.168.100.1"
            in commands
        )
        assert (
            "set vrf name relay_eth2 protocols static route 10.123.105.0/24 next-hop 192.168.100.1"
            in commands
        )
        assert (
            "set vrf name relay_eth3 protocols static route 10.101.105.0/24 next-hop 10.101.105.1"
            in commands
        )
        assert (
            "set vrf name relay_eth3 protocols static route 10.127.105.0/25 next-hop 10.127.105.1"
            in commands
        )

        # Egress VRF default routes (return path) - no gateway, so should NOT be present
        # Note: This test doesn't configure gateways on ingress interface
        egress_default_routes = [
            cmd for cmd in commands
            if "protocols static route 0.0.0.0/0" in cmd and "vrf relay_eth" in cmd
        ]
        # Should be empty because no ingress gateway is configured
        assert len(egress_default_routes) == 0

    def test_command_ordering(self):
        """Test that commands are generated in correct order.

        VyOS requires certain ordering constraints:
        1. VRF creation before interface binding
        2. VRF creation before policy routing
        3. All config before commit

        This test verifies the generator produces commands in correct order.
        """
        relay = RelayConfig(
            ingress_interface="eth1",
            pivots=[
                PivotConfig(
                    egress_interface="eth2",
                    targets=[
                        RelayTarget(
                            relay_prefix="10.32.5.0/24",
                            target_prefix="192.168.144.0/24",
                            gateway=IPv4Address("192.168.100.1"),
                        )
                    ],
                )
            ],
        )

        gen = RelayGenerator(relay)
        commands = gen.generate()

        # Find indices of key commands
        ingress_vrf_create_idx = commands.index("set vrf name relay_eth1 table 149")
        ingress_vrf_bind_idx = commands.index("set interfaces ethernet eth1 vrf relay_eth1")
        egress_vrf_create_idx = commands.index("set vrf name relay_eth2 table 150")
        egress_vrf_bind_idx = commands.index("set interfaces ethernet eth2 vrf relay_eth2")
        pbr_rule_idx = next(
            i for i, cmd in enumerate(commands) if "policy route relay-pbr rule" in cmd
        )
        dnat_idx = next(
            i for i, cmd in enumerate(commands) if "nat destination rule" in cmd
        )
        snat_idx = next(i for i, cmd in enumerate(commands) if "nat source rule" in cmd)
        proxy_arp_idx = commands.index(
            "set interfaces ethernet eth1 ip enable-proxy-arp"
        )
        proxy_arp_route_idx = next(
            i
            for i, cmd in enumerate(commands)
            if "vrf name relay_eth1" in cmd
            and "protocols static route" in cmd
            and "interface eth2" in cmd
        )
        egress_vrf_static_route_idx = next(
            i
            for i, cmd in enumerate(commands)
            if "vrf name relay_eth2" in cmd and "protocols static route" in cmd
        )

        # Verify ordering constraints
        assert ingress_vrf_create_idx < ingress_vrf_bind_idx, (
            "Ingress VRF must be created before binding interface"
        )
        assert egress_vrf_create_idx < egress_vrf_bind_idx, (
            "Egress VRF must be created before binding interface"
        )
        assert ingress_vrf_bind_idx < proxy_arp_route_idx, (
            "Interface binding before proxy-ARP routes"
        )
        assert egress_vrf_bind_idx < proxy_arp_route_idx, (
            "Interface binding before proxy-ARP routes"
        )
        assert proxy_arp_route_idx < pbr_rule_idx, "Proxy-ARP routes before PBR"
        assert pbr_rule_idx < dnat_idx, "PBR before NAT"
        assert dnat_idx < snat_idx, "DNAT before SNAT"
        assert snat_idx < proxy_arp_idx, "SNAT before proxy-ARP enable"
        assert proxy_arp_idx < egress_vrf_static_route_idx, (
            "Proxy-ARP enable before egress VRF static routes"
        )

    def test_vrf_naming_convention(self):
        """Test VRF naming follows 'relay_{interface}' convention."""
        relay = RelayConfig(
            ingress_interface="eth0",
            pivots=[
                PivotConfig(
                    egress_interface="eth5",
                    targets=[
                        RelayTarget(
                            relay_prefix="10.1.0.0/16",
                            target_prefix="192.168.0.0/16",
                            gateway=IPv4Address("192.168.1.1"),
                        )
                    ],
                )
            ],
        )

        gen = RelayGenerator(relay)
        commands = gen.generate()

        # Verify VRF naming follows convention for both ingress and egress
        assert "set vrf name relay_eth0 table 149" in commands
        assert "set interfaces ethernet eth0 vrf relay_eth0" in commands
        assert "set vrf name relay_eth5 table 150" in commands
        assert "set interfaces ethernet eth5 vrf relay_eth5" in commands
        assert any("vrf name relay_eth5 protocols static route" in cmd for cmd in commands)

    def test_rule_number_ranges(self):
        """Test that rule numbers fall in expected ranges.

        - Ingress VRF table ID: 149
        - Egress VRF table IDs: 150+
        - PBR rules: 10+, increment by 10
        - DNAT rules: 5000+, increment by 10
        - SNAT rules: 5000+, increment by 10
        """
        relay = RelayConfig(
            ingress_interface="eth1",
            pivots=[
                PivotConfig(
                    egress_interface="eth2",
                    targets=[
                        RelayTarget(
                            relay_prefix="10.1.0.0/24",
                            target_prefix="192.168.1.0/24",
                            gateway=IPv4Address("192.168.1.1"),
                        ),
                        RelayTarget(
                            relay_prefix="10.2.0.0/24",
                            target_prefix="192.168.2.0/24",
                            gateway=IPv4Address("192.168.2.1"),
                        ),
                    ],
                ),
                PivotConfig(
                    egress_interface="eth3",
                    targets=[
                        RelayTarget(
                            relay_prefix="10.3.0.0/24",
                            target_prefix="192.168.3.0/24",
                            gateway=IPv4Address("192.168.3.1"),
                        )
                    ],
                ),
            ],
        )

        gen = RelayGenerator(relay)
        commands = gen.generate()

        # VRF table IDs: 149 (ingress), 150, 151 (egress)
        assert "table 149" in " ".join(commands)
        assert "table 150" in " ".join(commands)
        assert "table 151" in " ".join(commands)

        # PBR rules: 10, 20, 30
        assert "rule 10 " in " ".join(commands)
        assert "rule 20 " in " ".join(commands)
        assert "rule 30 " in " ".join(commands)

        # DNAT rules: 5000, 5010, 5020
        assert "nat destination rule 5000" in " ".join(commands)
        assert "nat destination rule 5010" in " ".join(commands)
        assert "nat destination rule 5020" in " ".join(commands)

        # SNAT rules: 5000, 5010 (one per pivot)
        snat_commands = [cmd for cmd in commands if "nat source rule" in cmd]
        assert any("rule 5000" in cmd for cmd in snat_commands)
        assert any("rule 5010" in cmd for cmd in snat_commands)

    def test_masquerade_per_pivot_not_per_target(self):
        """Test SNAT masquerade is per-pivot, not per-target.

        Multiple targets on the same pivot should share one masquerade rule.
        """
        relay = RelayConfig(
            ingress_interface="eth1",
            pivots=[
                PivotConfig(
                    egress_interface="eth2",
                    targets=[
                        RelayTarget(
                            relay_prefix="10.1.0.0/24",
                            target_prefix="192.168.1.0/24",
                            gateway=IPv4Address("192.168.1.1"),
                        ),
                        RelayTarget(
                            relay_prefix="10.2.0.0/24",
                            target_prefix="192.168.2.0/24",
                            gateway=IPv4Address("192.168.2.1"),
                        ),
                        RelayTarget(
                            relay_prefix="10.3.0.0/24",
                            target_prefix="192.168.3.0/24",
                            gateway=IPv4Address("192.168.3.1"),
                        ),
                    ],
                )
            ],
        )

        gen = RelayGenerator(relay)
        commands = gen.generate()

        # Should have exactly one SNAT masquerade rule (2 commands: interface + masquerade)
        snat_commands = [cmd for cmd in commands if cmd.startswith("set nat source rule")]
        assert len(snat_commands) == 2
        assert "set nat source rule 5000 outbound-interface name eth2" in snat_commands
        assert "set nat source rule 5000 translation address masquerade" in snat_commands

        # Should NOT have rules 5010 or 5020 for SNAT (those are DNAT rules)
        assert not any("nat source rule 5010" in cmd for cmd in commands)
        assert not any("nat source rule 5020" in cmd for cmd in commands)

    def test_different_gateways_per_target(self):
        """Test that targets can have different gateways even in same pivot."""
        relay = RelayConfig(
            ingress_interface="eth1",
            pivots=[
                PivotConfig(
                    egress_interface="eth2",
                    targets=[
                        RelayTarget(
                            relay_prefix="10.1.0.0/24",
                            target_prefix="192.168.1.0/24",
                            gateway=IPv4Address("192.168.100.1"),  # Different gateway
                        ),
                        RelayTarget(
                            relay_prefix="10.2.0.0/24",
                            target_prefix="192.168.2.0/24",
                            gateway=IPv4Address("192.168.100.2"),  # Different gateway
                        ),
                    ],
                )
            ],
        )

        gen = RelayGenerator(relay)
        commands = gen.generate()

        # Verify both gateways are used in static routes
        assert (
            "set vrf name relay_eth2 protocols static route 192.168.1.0/24 next-hop 192.168.100.1"
            in commands
        )
        assert (
            "set vrf name relay_eth2 protocols static route 192.168.2.0/24 next-hop 192.168.100.2"
            in commands
        )

    def test_proxy_arp_only_on_ingress(self):
        """Test proxy-ARP is only enabled on ingress interface, not egress."""
        relay = RelayConfig(
            ingress_interface="eth1",
            pivots=[
                PivotConfig(
                    egress_interface="eth2",
                    targets=[
                        RelayTarget(
                            relay_prefix="10.1.0.0/24",
                            target_prefix="192.168.1.0/24",
                            gateway=IPv4Address("192.168.1.1"),
                        )
                    ],
                ),
                PivotConfig(
                    egress_interface="eth3",
                    targets=[
                        RelayTarget(
                            relay_prefix="10.2.0.0/24",
                            target_prefix="192.168.2.0/24",
                            gateway=IPv4Address("192.168.2.1"),
                        )
                    ],
                ),
            ],
        )

        gen = RelayGenerator(relay)
        commands = gen.generate()

        # Should only have proxy-ARP on ingress (eth1)
        proxy_arp_commands = [cmd for cmd in commands if "enable-proxy-arp" in cmd]
        assert len(proxy_arp_commands) == 1
        assert "set interfaces ethernet eth1 ip enable-proxy-arp" in proxy_arp_commands

        # Should NOT have proxy-ARP on egress interfaces
        assert not any("eth2 ip enable-proxy-arp" in cmd for cmd in commands)
        assert not any("eth3 ip enable-proxy-arp" in cmd for cmd in commands)

    def test_ingress_vrf_without_gateway(self):
        """Test that ingress VRF is created even when ingress interface has no gateway.

        When the ingress interface doesn't have a gateway configured, the ingress
        VRF should still be created but without a default route.
        """
        interfaces = [
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("10.40.0.1"),
                mask="255.255.0.0",
                # No gateway configured
            ),
            InterfaceConfig(
                name="eth2",
                ip=IPv4Address("192.168.100.1"),
                mask="255.255.255.0",
            ),
        ]

        relay = RelayConfig(
            ingress_interface="eth1",
            pivots=[
                PivotConfig(
                    egress_interface="eth2",
                    targets=[
                        RelayTarget(
                            relay_prefix="10.32.5.0/24",
                            target_prefix="192.168.144.0/24",
                            gateway=IPv4Address("192.168.100.254"),
                        )
                    ],
                )
            ],
        )

        gen = RelayGenerator(relay, interfaces)
        commands = gen.generate()

        # Ingress VRF should still be created
        assert "set vrf name relay_eth1 table 149" in commands
        assert "set interfaces ethernet eth1 vrf relay_eth1" in commands

        # But no default route in ingress VRF since no gateway
        ingress_default_route = [
            cmd
            for cmd in commands
            if "vrf name relay_eth1" in cmd and "protocols static route 0.0.0.0/0" in cmd
        ]
        assert len(ingress_default_route) == 0

        # Egress VRF and routes should still work
        assert "set vrf name relay_eth2 table 150" in commands
        assert (
            "set vrf name relay_eth2 protocols static route 192.168.144.0/24 "
            "next-hop 192.168.100.254" in commands
        )
