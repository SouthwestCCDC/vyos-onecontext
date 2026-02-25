"""Tests for VXLAN models."""

import pytest
from pydantic import ValidationError

from vyos_onecontext.models import BridgeConfig, VxlanConfig, VxlanTunnelConfig


class TestVxlanTunnelConfig:
    """Tests for VxlanTunnelConfig model."""

    def test_valid_vxlan_tunnel(self) -> None:
        """Test valid VXLAN tunnel configuration."""
        tunnel = VxlanTunnelConfig(
            name="vxlan0",
            vni=100,
            remote="10.128.1.2",
            source_address="10.128.1.1",
            description="Tunnel to site B",
        )
        assert tunnel.name == "vxlan0"
        assert tunnel.vni == 100
        assert str(tunnel.remote) == "10.128.1.2"
        assert str(tunnel.source_address) == "10.128.1.1"
        assert tunnel.description == "Tunnel to site B"

    def test_minimal_vxlan_tunnel(self) -> None:
        """Test minimal VXLAN tunnel configuration."""
        tunnel = VxlanTunnelConfig(
            name="vxlan1", vni=200, remote="192.168.1.1", source_address="192.168.1.2"
        )
        assert tunnel.description == ""

    def test_invalid_vxlan_name(self) -> None:
        """Test that invalid VXLAN names are rejected."""
        # Must be vxlanN format
        with pytest.raises(ValidationError, match="Invalid VXLAN interface name"):
            VxlanTunnelConfig(
                name="vxl0", vni=100, remote="10.0.0.1", source_address="10.0.0.2"
            )

        with pytest.raises(ValidationError, match="Invalid VXLAN interface name"):
            VxlanTunnelConfig(
                name="vxlan", vni=100, remote="10.0.0.1", source_address="10.0.0.2"
            )

        with pytest.raises(ValidationError, match="Invalid VXLAN interface name"):
            VxlanTunnelConfig(
                name="eth0", vni=100, remote="10.0.0.1", source_address="10.0.0.2"
            )

    def test_vni_bounds(self) -> None:
        """Test VNI validation bounds."""
        # Valid VNI
        VxlanTunnelConfig(
            name="vxlan0", vni=1, remote="10.0.0.1", source_address="10.0.0.2"
        )
        VxlanTunnelConfig(
            name="vxlan0", vni=16777215, remote="10.0.0.1", source_address="10.0.0.2"
        )

        # VNI too small
        with pytest.raises(ValidationError):
            VxlanTunnelConfig(
                name="vxlan0", vni=0, remote="10.0.0.1", source_address="10.0.0.2"
            )

        # VNI too large
        with pytest.raises(ValidationError):
            VxlanTunnelConfig(
                name="vxlan0", vni=16777216, remote="10.0.0.1", source_address="10.0.0.2"
            )

    def test_invalid_ip_addresses(self) -> None:
        """Test that invalid IP addresses are rejected."""
        with pytest.raises(ValidationError):
            VxlanTunnelConfig(
                name="vxlan0", vni=100, remote="not-an-ip", source_address="10.0.0.2"
            )

        with pytest.raises(ValidationError):
            VxlanTunnelConfig(
                name="vxlan0", vni=100, remote="10.0.0.1", source_address="256.0.0.1"
            )


class TestBridgeConfig:
    """Tests for BridgeConfig model."""

    def test_valid_bridge(self) -> None:
        """Test valid bridge configuration."""
        bridge = BridgeConfig(
            name="br0",
            address="172.22.1.1/16",
            members=["eth1", "vxlan0", "vxlan1"],
            description="Arcade network bridge",
        )
        assert bridge.name == "br0"
        assert bridge.address == "172.22.1.1/16"
        assert bridge.members == ["eth1", "vxlan0", "vxlan1"]
        assert bridge.description == "Arcade network bridge"

    def test_minimal_bridge(self) -> None:
        """Test minimal bridge configuration."""
        bridge = BridgeConfig(name="br1", address="10.0.0.1/24", members=["eth0"])
        assert bridge.description == ""

    def test_invalid_bridge_name(self) -> None:
        """Test that invalid bridge names are rejected."""
        # Must be brN format
        with pytest.raises(ValidationError, match="Invalid bridge interface name"):
            BridgeConfig(name="bridge0", address="10.0.0.1/24", members=["eth0"])

        with pytest.raises(ValidationError, match="Invalid bridge interface name"):
            BridgeConfig(name="br", address="10.0.0.1/24", members=["eth0"])

        with pytest.raises(ValidationError, match="Invalid bridge interface name"):
            BridgeConfig(name="br-arcade", address="10.0.0.1/24", members=["eth0"])

    def test_invalid_address(self) -> None:
        """Test that invalid addresses are rejected."""
        # Must be CIDR notation
        with pytest.raises(ValidationError, match="Invalid CIDR address"):
            BridgeConfig(name="br0", address="10.0.0.1", members=["eth0"])

        with pytest.raises(ValidationError, match="Invalid CIDR address"):
            BridgeConfig(name="br0", address="not-a-cidr", members=["eth0"])

        with pytest.raises(ValidationError, match="Invalid CIDR address"):
            BridgeConfig(name="br0", address="10.0.0.1/33", members=["eth0"])

    def test_empty_members(self) -> None:
        """Test that empty members list is rejected."""
        with pytest.raises(ValidationError, match="at least one member"):
            BridgeConfig(name="br0", address="10.0.0.1/24", members=[])

    def test_invalid_member_names(self) -> None:
        """Test that invalid member names are rejected."""
        # Must be ethN or vxlanN
        with pytest.raises(ValidationError, match="Invalid bridge member interface name"):
            BridgeConfig(name="br0", address="10.0.0.1/24", members=["wlan0"])

        with pytest.raises(ValidationError, match="Invalid bridge member interface name"):
            BridgeConfig(name="br0", address="10.0.0.1/24", members=["eth0", "invalid"])

    def test_duplicate_members(self) -> None:
        """Test that duplicate members are rejected."""
        with pytest.raises(ValidationError, match="duplicate"):
            BridgeConfig(name="br0", address="10.0.0.1/24", members=["eth0", "eth0"])

        with pytest.raises(ValidationError, match="duplicate"):
            BridgeConfig(
                name="br0", address="10.0.0.1/24", members=["eth0", "vxlan0", "eth0"]
            )


class TestVxlanConfig:
    """Tests for VxlanConfig model."""

    def test_valid_vxlan_config(self) -> None:
        """Test valid VXLAN configuration."""
        config = VxlanConfig(
            tunnels=[
                VxlanTunnelConfig(
                    name="vxlan0", vni=100, remote="10.128.1.2", source_address="10.128.1.1"
                ),
                VxlanTunnelConfig(
                    name="vxlan1", vni=101, remote="10.128.1.3", source_address="10.128.1.1"
                ),
            ],
            bridges=[
                BridgeConfig(
                    name="br0", address="172.22.1.1/16", members=["eth1", "vxlan0", "vxlan1"]
                )
            ],
        )
        assert len(config.tunnels) == 2
        assert len(config.bridges) == 1

    def test_empty_vxlan_config(self) -> None:
        """Test empty VXLAN configuration."""
        config = VxlanConfig()
        assert config.tunnels == []
        assert config.bridges == []

    def test_duplicate_tunnel_names(self) -> None:
        """Test that duplicate tunnel names are rejected."""
        with pytest.raises(ValidationError, match="tunnel names must be unique"):
            VxlanConfig(
                tunnels=[
                    VxlanTunnelConfig(
                        name="vxlan0", vni=100, remote="10.0.0.1", source_address="10.0.0.2"
                    ),
                    VxlanTunnelConfig(
                        name="vxlan0", vni=101, remote="10.0.0.3", source_address="10.0.0.2"
                    ),
                ]
            )

    def test_duplicate_bridge_names(self) -> None:
        """Test that duplicate bridge names are rejected."""
        with pytest.raises(ValidationError, match="Bridge names must be unique"):
            VxlanConfig(
                bridges=[
                    BridgeConfig(name="br0", address="10.0.0.1/24", members=["eth0"]),
                    BridgeConfig(name="br0", address="10.0.1.1/24", members=["eth1"]),
                ]
            )

    def test_undefined_vxlan_in_bridge(self) -> None:
        """Test that bridges cannot reference undefined VXLAN interfaces."""
        with pytest.raises(ValidationError, match="undefined VXLAN interface"):
            VxlanConfig(
                tunnels=[
                    VxlanTunnelConfig(
                        name="vxlan0", vni=100, remote="10.0.0.1", source_address="10.0.0.2"
                    )
                ],
                bridges=[
                    BridgeConfig(
                        name="br0", address="10.0.0.1/24", members=["eth0", "vxlan99"]
                    )
                ],
            )

    def test_bridge_with_eth_only(self) -> None:
        """Test bridge with only ethernet members (no VXLAN)."""
        config = VxlanConfig(
            bridges=[BridgeConfig(name="br0", address="10.0.0.1/24", members=["eth0", "eth1"])]
        )
        assert len(config.bridges) == 1
        assert len(config.tunnels) == 0

    def test_vxlan_without_bridges(self) -> None:
        """Test VXLAN tunnels without bridges (should be valid but uncommon)."""
        config = VxlanConfig(
            tunnels=[
                VxlanTunnelConfig(
                    name="vxlan0", vni=100, remote="10.0.0.1", source_address="10.0.0.2"
                )
            ]
        )
        assert len(config.tunnels) == 1
        assert len(config.bridges) == 0
