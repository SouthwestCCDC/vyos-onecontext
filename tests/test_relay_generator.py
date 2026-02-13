"""Tests for RelayGenerator.

This module tests the VRF-based relay configuration generator, verifying that
it produces correct VyOS commands for VRF creation, policy-based routing,
NAT (DNAT/SNAT), proxy-ARP, and VRF-scoped static routes.
"""

from ipaddress import IPv4Address

from vyos_onecontext.generators.relay import RelayGenerator
from vyos_onecontext.models.relay import PivotConfig, RelayConfig, RelayTarget


class TestRelayGenerator:
    """Tests for RelayGenerator command generation."""

    def test_generate_with_none_config(self):
        """Test generator returns empty list when relay config is None."""
        gen = RelayGenerator(None)
        commands = gen.generate()

        assert len(commands) == 0

    def test_generate_single_pivot_single_target(self):
        """Test relay config with one pivot and one target.

        This is the simplest relay configuration: single egress interface,
        single target network. Verifies all command types are generated.
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

        # Expected commands (in order):
        # 1. VRF creation and interface binding
        assert "set vrf name relay_eth2 table 200" in commands
        assert "set interfaces ethernet eth2 vrf relay_eth2" in commands

        # 2. Policy-based routing
        assert "set policy route relay-pbr rule 10 destination address 10.32.5.0/24" in commands
        assert "set policy route relay-pbr rule 10 set table 200" in commands
        assert "set interfaces ethernet eth1 policy route relay-pbr" in commands

        # 3. Destination NAT
        assert "set nat destination rule 5000 inbound-interface name eth1" in commands
        assert "set nat destination rule 5000 destination address 10.32.5.0/24" in commands
        assert "set nat destination rule 5000 translation address 192.168.144.0/24" in commands

        # 4. Source NAT (masquerade)
        assert "set nat source rule 5000 outbound-interface name eth2" in commands
        assert "set nat source rule 5000 translation address masquerade" in commands

        # 5. Proxy-ARP
        assert "set interfaces ethernet eth1 ip enable-proxy-arp" in commands

        # 6. Static routes in VRF
        assert (
            "set vrf name relay_eth2 protocols static route 192.168.144.0/24 next-hop 192.168.100.1"
            in commands
        )

    def test_generate_single_pivot_multiple_targets(self):
        """Test relay config with one pivot and multiple targets.

        Verifies that multiple targets on the same pivot share:
        - Same VRF (one VRF per pivot)
        - Same SNAT rule (one masquerade per pivot)
        But have separate:
        - PBR rules (one per target)
        - DNAT rules (one per target)
        - Static routes (one per target)
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
                )
            ],
        )

        gen = RelayGenerator(relay)
        commands = gen.generate()

        # VRF: Only one VRF for both targets (same pivot)
        vrf_commands = [cmd for cmd in commands if cmd.startswith("set vrf name relay_eth2")]
        assert len(vrf_commands) == 3  # 1 VRF creation + 2 static routes

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

        # Static routes: Two routes (one per target)
        static_routes = [cmd for cmd in commands if "protocols static route" in cmd]
        assert len(static_routes) == 2
        assert any("192.168.144.0/24" in cmd for cmd in static_routes)
        assert any("10.123.105.0/24" in cmd for cmd in static_routes)

    def test_generate_multiple_pivots_multiple_targets(self):
        """Test relay config with multiple pivots and multiple targets.

        This is the full-featured scenario: multiple egress interfaces,
        each with multiple targets. Verifies:
        - VRF table IDs are sequential (200, 201, ...)
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

        # VRF creation: Two VRFs with sequential table IDs
        assert "set vrf name relay_eth2 table 200" in commands
        assert "set vrf name relay_eth3 table 201" in commands
        assert "set interfaces ethernet eth2 vrf relay_eth2" in commands
        assert "set interfaces ethernet eth3 vrf relay_eth3" in commands

        # PBR: Four rules (one per target) with correct table routing
        assert "set policy route relay-pbr rule 10 destination address 10.32.5.0/24" in commands
        assert "set policy route relay-pbr rule 10 set table 200" in commands
        assert "set policy route relay-pbr rule 20 destination address 10.33.5.0/24" in commands
        assert "set policy route relay-pbr rule 20 set table 200" in commands
        assert "set policy route relay-pbr rule 30 destination address 10.36.5.0/24" in commands
        assert "set policy route relay-pbr rule 30 set table 201" in commands
        assert "set policy route relay-pbr rule 40 destination address 10.36.105.0/25" in commands
        assert "set policy route relay-pbr rule 40 set table 201" in commands

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

        # Static routes: Four routes in correct VRFs
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
        vrf_create_idx = commands.index("set vrf name relay_eth2 table 200")
        vrf_bind_idx = commands.index("set interfaces ethernet eth2 vrf relay_eth2")
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
        static_route_idx = next(
            i for i, cmd in enumerate(commands) if "protocols static route" in cmd
        )

        # Verify ordering constraints
        assert vrf_create_idx < vrf_bind_idx, "VRF must be created before binding interface"
        assert vrf_bind_idx < pbr_rule_idx, "Interface binding before PBR"
        assert pbr_rule_idx < dnat_idx, "PBR before NAT"
        assert dnat_idx < snat_idx, "DNAT before SNAT"
        assert snat_idx < proxy_arp_idx, "SNAT before proxy-ARP"
        assert proxy_arp_idx < static_route_idx, "Proxy-ARP before static routes"

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

        # Verify VRF name follows convention
        assert "set vrf name relay_eth5 table 200" in commands
        assert "set interfaces ethernet eth5 vrf relay_eth5" in commands
        assert any("vrf name relay_eth5 protocols static route" in cmd for cmd in commands)

    def test_rule_number_ranges(self):
        """Test that rule numbers fall in expected ranges.

        - VRF table IDs: 200+
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

        # VRF table IDs: 200, 201
        assert "table 200" in " ".join(commands)
        assert "table 201" in " ".join(commands)

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
