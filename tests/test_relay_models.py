"""Tests for relay configuration models."""

import pytest
from pydantic import ValidationError

from vyos_onecontext.models import PivotConfig, RelayConfig, RelayTarget


class TestRelayTarget:
    """Tests for RelayTarget model."""

    def test_valid_target(self) -> None:
        """Test valid relay target configuration."""
        target = RelayTarget(
            relay_prefix="10.32.5.0/24",
            target_prefix="192.168.144.0/24",
            gateway="192.168.100.1",
        )
        assert target.relay_prefix == "10.32.5.0/24"
        assert target.target_prefix == "192.168.144.0/24"
        assert str(target.gateway) == "192.168.100.1"

    def test_various_prefix_lengths(self) -> None:
        """Test relay targets with various CIDR prefix lengths."""
        # /16
        target_16 = RelayTarget(
            relay_prefix="10.32.0.0/16",
            target_prefix="192.168.0.0/16",
            gateway="192.168.100.1",
        )
        assert target_16.relay_prefix == "10.32.0.0/16"

        # /28
        target_28 = RelayTarget(
            relay_prefix="10.32.5.0/28",
            target_prefix="192.168.144.0/28",
            gateway="192.168.100.1",
        )
        assert target_28.relay_prefix == "10.32.5.0/28"

        # /25
        target_25 = RelayTarget(
            relay_prefix="10.36.105.0/25",
            target_prefix="10.127.105.0/25",
            gateway="10.127.105.1",
        )
        assert target_25.relay_prefix == "10.36.105.0/25"

    def test_mismatched_prefix_lengths(self) -> None:
        """Test that mismatched prefix lengths are rejected."""
        with pytest.raises(
            ValidationError, match="relay_prefix.*target_prefix.*matching prefix lengths"
        ):
            RelayTarget(
                relay_prefix="10.32.5.0/24",
                target_prefix="192.168.144.0/25",
                gateway="192.168.100.1",
            )

    def test_invalid_relay_prefix(self) -> None:
        """Test that invalid relay prefix is rejected."""
        with pytest.raises(ValidationError, match="Invalid CIDR notation"):
            RelayTarget(
                relay_prefix="10.32.5.0/33",  # Invalid prefix length
                target_prefix="192.168.144.0/24",
                gateway="192.168.100.1",
            )

    def test_invalid_target_prefix(self) -> None:
        """Test that invalid target prefix is rejected."""
        with pytest.raises(ValidationError, match="Invalid CIDR notation"):
            RelayTarget(
                relay_prefix="10.32.5.0/24",
                target_prefix="not-a-cidr",
                gateway="192.168.100.1",
            )

    def test_invalid_gateway(self) -> None:
        """Test that invalid gateway IP is rejected."""
        with pytest.raises(ValidationError):
            RelayTarget(
                relay_prefix="10.32.5.0/24",
                target_prefix="192.168.144.0/24",
                gateway="999.999.999.999",  # type: ignore
            )


class TestPivotConfig:
    """Tests for PivotConfig model."""

    def test_valid_pivot_single_target(self) -> None:
        """Test valid pivot with single target."""
        pivot = PivotConfig(
            egress_interface="eth2",
            targets=[
                RelayTarget(
                    relay_prefix="10.32.5.0/24",
                    target_prefix="192.168.144.0/24",
                    gateway="192.168.100.1",
                )
            ],
        )
        assert pivot.egress_interface == "eth2"
        assert len(pivot.targets) == 1

    def test_valid_pivot_multiple_targets(self) -> None:
        """Test valid pivot with multiple targets."""
        pivot = PivotConfig(
            egress_interface="eth2",
            targets=[
                RelayTarget(
                    relay_prefix="10.32.5.0/24",
                    target_prefix="192.168.144.0/24",
                    gateway="192.168.100.1",
                ),
                RelayTarget(
                    relay_prefix="10.33.5.0/24",
                    target_prefix="10.123.105.0/24",
                    gateway="192.168.100.1",
                ),
            ],
        )
        assert len(pivot.targets) == 2

    def test_empty_targets_list(self) -> None:
        """Test that empty targets list is rejected."""
        with pytest.raises(ValidationError, match="at least one target"):
            PivotConfig(egress_interface="eth2", targets=[])

    def test_invalid_interface_format(self) -> None:
        """Test that invalid interface format is rejected."""
        with pytest.raises(ValidationError, match="Invalid interface name"):
            PivotConfig(
                egress_interface="wlan0",  # Not ethN format
                targets=[
                    RelayTarget(
                        relay_prefix="10.32.5.0/24",
                        target_prefix="192.168.144.0/24",
                        gateway="192.168.100.1",
                    )
                ],
            )

    def test_interface_not_ethN(self) -> None:
        """Test that non-ethN interface names are rejected."""
        with pytest.raises(ValidationError, match="Invalid interface name"):
            PivotConfig(
                egress_interface="ens192",
                targets=[
                    RelayTarget(
                        relay_prefix="10.32.5.0/24",
                        target_prefix="192.168.144.0/24",
                        gateway="192.168.100.1",
                    )
                ],
            )


class TestRelayConfig:
    """Tests for RelayConfig model."""

    def test_minimal_valid_config(self) -> None:
        """Test minimal valid relay configuration."""
        config = RelayConfig(
            ingress_interface="eth1",
            pivots=[
                PivotConfig(
                    egress_interface="eth2",
                    targets=[
                        RelayTarget(
                            relay_prefix="10.32.5.0/24",
                            target_prefix="192.168.144.0/24",
                            gateway="192.168.100.1",
                        )
                    ],
                )
            ],
        )
        assert config.ingress_interface == "eth1"
        assert len(config.pivots) == 1

    def test_multiple_pivots_multiple_targets(self) -> None:
        """Test configuration with multiple pivots and targets."""
        config = RelayConfig(
            ingress_interface="eth1",
            pivots=[
                PivotConfig(
                    egress_interface="eth2",
                    targets=[
                        RelayTarget(
                            relay_prefix="10.32.5.0/24",
                            target_prefix="192.168.144.0/24",
                            gateway="192.168.100.1",
                        ),
                        RelayTarget(
                            relay_prefix="10.33.5.0/24",
                            target_prefix="10.123.105.0/24",
                            gateway="192.168.100.1",
                        ),
                    ],
                ),
                PivotConfig(
                    egress_interface="eth3",
                    targets=[
                        RelayTarget(
                            relay_prefix="10.36.5.0/24",
                            target_prefix="10.101.105.0/24",
                            gateway="10.101.105.1",
                        ),
                        RelayTarget(
                            relay_prefix="10.36.105.0/25",
                            target_prefix="10.127.105.0/25",
                            gateway="10.127.105.1",
                        ),
                    ],
                ),
            ],
        )
        assert len(config.pivots) == 2
        assert len(config.pivots[0].targets) == 2
        assert len(config.pivots[1].targets) == 2

    def test_empty_pivots_list(self) -> None:
        """Test that empty pivots list is rejected."""
        with pytest.raises(ValidationError, match="At least one pivot is required"):
            RelayConfig(ingress_interface="eth1", pivots=[])

    def test_duplicate_egress_interfaces(self) -> None:
        """Test that duplicate egress interfaces are rejected."""
        with pytest.raises(ValidationError, match="Duplicate egress interfaces.*eth2"):
            RelayConfig(
                ingress_interface="eth1",
                pivots=[
                    PivotConfig(
                        egress_interface="eth2",
                        targets=[
                            RelayTarget(
                                relay_prefix="10.32.5.0/24",
                                target_prefix="192.168.144.0/24",
                                gateway="192.168.100.1",
                            )
                        ],
                    ),
                    PivotConfig(
                        egress_interface="eth2",  # Duplicate
                        targets=[
                            RelayTarget(
                                relay_prefix="10.33.5.0/24",
                                target_prefix="10.123.105.0/24",
                                gateway="192.168.100.1",
                            )
                        ],
                    ),
                ],
            )

    def test_ingress_equals_egress(self) -> None:
        """Test that ingress interface cannot be used as egress."""
        with pytest.raises(
            ValidationError, match="ingress_interface.*cannot be used as an egress_interface"
        ):
            RelayConfig(
                ingress_interface="eth1",
                pivots=[
                    PivotConfig(
                        egress_interface="eth1",  # Same as ingress
                        targets=[
                            RelayTarget(
                                relay_prefix="10.32.5.0/24",
                                target_prefix="192.168.144.0/24",
                                gateway="192.168.100.1",
                            )
                        ],
                    )
                ],
            )

    def test_overlapping_relay_prefixes_same_pivot(self) -> None:
        """Test that overlapping relay prefixes are rejected (same pivot)."""
        with pytest.raises(ValidationError, match="Overlapping relay prefixes"):
            RelayConfig(
                ingress_interface="eth1",
                pivots=[
                    PivotConfig(
                        egress_interface="eth2",
                        targets=[
                            RelayTarget(
                                relay_prefix="10.32.5.0/24",
                                target_prefix="192.168.144.0/24",
                                gateway="192.168.100.1",
                            ),
                            RelayTarget(
                                relay_prefix="10.32.5.0/25",  # Overlaps with /24
                                target_prefix="10.123.105.0/25",
                                gateway="192.168.100.1",
                            ),
                        ],
                    )
                ],
            )

    def test_overlapping_relay_prefixes_different_pivots(self) -> None:
        """Test that overlapping relay prefixes are rejected (different pivots)."""
        with pytest.raises(ValidationError, match="Overlapping relay prefixes"):
            RelayConfig(
                ingress_interface="eth1",
                pivots=[
                    PivotConfig(
                        egress_interface="eth2",
                        targets=[
                            RelayTarget(
                                relay_prefix="10.32.5.0/24",
                                target_prefix="192.168.144.0/24",
                                gateway="192.168.100.1",
                            )
                        ],
                    ),
                    PivotConfig(
                        egress_interface="eth3",
                        targets=[
                            RelayTarget(
                                relay_prefix="10.32.5.0/24",  # Exact duplicate
                                target_prefix="10.123.105.0/24",
                                gateway="10.123.105.1",
                            )
                        ],
                    ),
                ],
            )

    def test_invalid_ingress_interface_format(self) -> None:
        """Test that invalid ingress interface format is rejected."""
        with pytest.raises(ValidationError, match="Invalid interface name"):
            RelayConfig(
                ingress_interface="wlan0",
                pivots=[
                    PivotConfig(
                        egress_interface="eth2",
                        targets=[
                            RelayTarget(
                                relay_prefix="10.32.5.0/24",
                                target_prefix="192.168.144.0/24",
                                gateway="192.168.100.1",
                            )
                        ],
                    )
                ],
            )
