"""Tests for VXLAN generator."""

from vyos_onecontext.generators import VxlanGenerator
from vyos_onecontext.models import BridgeConfig, VxlanConfig, VxlanTunnelConfig


class TestVxlanGenerator:
    """Tests for VxlanGenerator."""

    def test_no_vxlan_config(self) -> None:
        """Test generator with no VXLAN configuration."""
        gen = VxlanGenerator(None)
        commands = gen.generate()
        assert commands == []

    def test_single_tunnel(self) -> None:
        """Test generation of a single VXLAN tunnel."""
        config = VxlanConfig(
            tunnels=[
                VxlanTunnelConfig(
                    name="vxlan0",
                    vni=100,
                    remote="10.128.1.2",
                    source_address="10.128.1.1",
                    description="Test tunnel",
                )
            ]
        )
        gen = VxlanGenerator(config)
        commands = gen.generate()

        assert "set interfaces vxlan vxlan0 vni 100" in commands
        assert "set interfaces vxlan vxlan0 remote 10.128.1.2" in commands
        assert "set interfaces vxlan vxlan0 source-address 10.128.1.1" in commands
        assert "set interfaces vxlan vxlan0 description 'Test tunnel'" in commands

    def test_tunnel_without_description(self) -> None:
        """Test tunnel generation without description."""
        config = VxlanConfig(
            tunnels=[
                VxlanTunnelConfig(
                    name="vxlan0", vni=100, remote="10.0.0.1", source_address="10.0.0.2"
                )
            ]
        )
        gen = VxlanGenerator(config)
        commands = gen.generate()

        # Should not include description command
        assert all("description" not in cmd for cmd in commands)
        assert len(commands) == 3  # vni, remote, source-address

    def test_multiple_tunnels(self) -> None:
        """Test generation of multiple VXLAN tunnels."""
        config = VxlanConfig(
            tunnels=[
                VxlanTunnelConfig(
                    name="vxlan0", vni=100, remote="10.128.1.2", source_address="10.128.1.1"
                ),
                VxlanTunnelConfig(
                    name="vxlan1", vni=101, remote="10.128.1.3", source_address="10.128.1.1"
                ),
            ]
        )
        gen = VxlanGenerator(config)
        commands = gen.generate()

        # Check first tunnel
        assert "set interfaces vxlan vxlan0 vni 100" in commands
        assert "set interfaces vxlan vxlan0 remote 10.128.1.2" in commands
        assert "set interfaces vxlan vxlan0 source-address 10.128.1.1" in commands

        # Check second tunnel
        assert "set interfaces vxlan vxlan1 vni 101" in commands
        assert "set interfaces vxlan vxlan1 remote 10.128.1.3" in commands
        assert "set interfaces vxlan vxlan1 source-address 10.128.1.1" in commands

    def test_single_bridge(self) -> None:
        """Test generation of a single bridge."""
        config = VxlanConfig(
            tunnels=[
                VxlanTunnelConfig(
                    name="vxlan0", vni=100, remote="10.0.0.1", source_address="10.0.0.2"
                )
            ],
            bridges=[
                BridgeConfig(
                    name="br0",
                    address="172.22.1.1/16",
                    members=["eth1", "vxlan0"],
                    description="Arcade bridge",
                )
            ],
        )
        gen = VxlanGenerator(config)
        commands = gen.generate()

        assert "set interfaces bridge br0 member interface eth1" in commands
        assert "set interfaces bridge br0 member interface vxlan0" in commands
        assert "set interfaces bridge br0 address 172.22.1.1/16" in commands
        assert "set interfaces bridge br0 description 'Arcade bridge'" in commands

    def test_bridge_without_description(self) -> None:
        """Test bridge generation without description."""
        config = VxlanConfig(
            bridges=[BridgeConfig(name="br0", address="10.0.0.1/24", members=["eth0"])]
        )
        gen = VxlanGenerator(config)
        commands = gen.generate()

        # Should not include description command
        assert all("description" not in cmd for cmd in commands)

    def test_bridge_with_multiple_members(self) -> None:
        """Test bridge with multiple members."""
        config = VxlanConfig(
            tunnels=[
                VxlanTunnelConfig(
                    name="vxlan0", vni=100, remote="10.0.0.1", source_address="10.0.0.2"
                ),
                VxlanTunnelConfig(
                    name="vxlan1", vni=101, remote="10.0.0.3", source_address="10.0.0.2"
                ),
                VxlanTunnelConfig(
                    name="vxlan2", vni=102, remote="10.0.0.4", source_address="10.0.0.2"
                ),
            ],
            bridges=[
                BridgeConfig(
                    name="br0",
                    address="172.22.0.1/16",
                    members=["eth1", "vxlan0", "vxlan1", "vxlan2"],
                )
            ],
        )
        gen = VxlanGenerator(config)
        commands = gen.generate()

        # Check all members are added
        assert "set interfaces bridge br0 member interface eth1" in commands
        assert "set interfaces bridge br0 member interface vxlan0" in commands
        assert "set interfaces bridge br0 member interface vxlan1" in commands
        assert "set interfaces bridge br0 member interface vxlan2" in commands
        assert "set interfaces bridge br0 address 172.22.0.1/16" in commands

    def test_complete_vxlan_config(self) -> None:
        """Test complete VXLAN configuration with tunnels and bridges."""
        config = VxlanConfig(
            tunnels=[
                VxlanTunnelConfig(
                    name="vxlan0",
                    vni=100,
                    remote="10.128.37.1",
                    source_address="10.128.1.1",
                    description="Tunnel to Store 37",
                ),
                VxlanTunnelConfig(
                    name="vxlan1",
                    vni=101,
                    remote="10.128.114.1",
                    source_address="10.128.1.1",
                    description="Tunnel to Store 114",
                ),
            ],
            bridges=[
                BridgeConfig(
                    name="br0",
                    address="172.22.1.1/16",
                    members=["eth2", "vxlan0", "vxlan1"],
                    description="Arcade network",
                )
            ],
        )
        gen = VxlanGenerator(config)
        commands = gen.generate()

        # Check tunnels come before bridges in output
        vxlan0_idx = next(i for i, cmd in enumerate(commands) if "vxlan vxlan0" in cmd)
        vxlan1_idx = next(i for i, cmd in enumerate(commands) if "vxlan vxlan1" in cmd)
        bridge_idx = next(i for i, cmd in enumerate(commands) if "bridge br0" in cmd)

        assert vxlan0_idx < bridge_idx
        assert vxlan1_idx < bridge_idx

        # Verify all expected commands exist
        assert "set interfaces vxlan vxlan0 vni 100" in commands
        assert "set interfaces vxlan vxlan1 vni 101" in commands
        assert "set interfaces bridge br0 member interface eth2" in commands
        assert "set interfaces bridge br0 member interface vxlan0" in commands
        assert "set interfaces bridge br0 member interface vxlan1" in commands
        assert "set interfaces bridge br0 address 172.22.1.1/16" in commands

    def test_multiple_bridges(self) -> None:
        """Test multiple bridges (uncommon but valid)."""
        config = VxlanConfig(
            bridges=[
                BridgeConfig(name="br0", address="10.0.0.1/24", members=["eth0", "eth1"]),
                BridgeConfig(name="br1", address="10.0.1.1/24", members=["eth2", "eth3"]),
            ]
        )
        gen = VxlanGenerator(config)
        commands = gen.generate()

        # Check both bridges configured
        assert "set interfaces bridge br0 member interface eth0" in commands
        assert "set interfaces bridge br0 member interface eth1" in commands
        assert "set interfaces bridge br0 address 10.0.0.1/24" in commands

        assert "set interfaces bridge br1 member interface eth2" in commands
        assert "set interfaces bridge br1 member interface eth3" in commands
        assert "set interfaces bridge br1 address 10.0.1.1/24" in commands

    def test_empty_vxlan_config(self) -> None:
        """Test with empty VXLAN config (no tunnels or bridges)."""
        config = VxlanConfig()
        gen = VxlanGenerator(config)
        commands = gen.generate()

        assert commands == []
