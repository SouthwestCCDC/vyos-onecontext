"""Relay configuration models for VRF-based scoring relay."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network
from typing import Annotated

from pydantic import BaseModel, Field, field_validator, model_validator

from vyos_onecontext.models.interface import _validate_interface_name


class RelayTarget(BaseModel):
    """A single relay target (relay prefix -> target network).

    Defines a mapping from a relay address range (visible to scoring) to an
    actual target network address range, with subnet-to-subnet NAT translation.
    """

    relay_prefix: Annotated[str, Field(description="Relay address range (CIDR notation)")]
    target_prefix: Annotated[str, Field(description="Target network range (CIDR notation)")]
    gateway: Annotated[IPv4Address, Field(description="Next-hop gateway for target network")]

    @field_validator("relay_prefix", "target_prefix")
    @classmethod
    def validate_prefix(cls, v: str) -> str:
        """Validate IPv4 CIDR notation."""
        try:
            IPv4Network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation: {v}") from e
        return v

    @model_validator(mode="after")
    def validate_prefix_lengths_match(self) -> RelayTarget:
        """Ensure relay_prefix and target_prefix have matching prefix lengths.

        VyOS subnet-to-subnet NAT (netmap) requires identical prefix lengths.
        """
        relay_net = IPv4Network(self.relay_prefix, strict=False)
        target_net = IPv4Network(self.target_prefix, strict=False)
        if relay_net.prefixlen != target_net.prefixlen:
            raise ValueError(
                f"relay_prefix ({self.relay_prefix}) and target_prefix "
                f"({self.target_prefix}) must have matching prefix lengths"
            )
        return self


class PivotConfig(BaseModel):
    """A routing pivot (egress interface + targets).

    A pivot represents a routing domain (VRF) with one egress interface and
    one or more target networks reachable via that interface.
    """

    egress_interface: Annotated[str, Field(description="Egress interface for this pivot")]
    targets: Annotated[list[RelayTarget], Field(description="Target networks for this pivot")]

    @field_validator("egress_interface")
    @classmethod
    def validate_interface_format(cls, v: str) -> str:
        """Validate interface name format."""
        return _validate_interface_name(v)

    @model_validator(mode="after")
    def validate_has_targets(self) -> PivotConfig:
        """Ensure at least one target per pivot."""
        if not self.targets:
            raise ValueError("Each pivot must have at least one target")
        return self


class RelayConfig(BaseModel):
    """Complete relay router configuration.

    Defines VRF-based relay configuration with ingress interface and multiple
    routing pivots, each handling traffic to different target networks.
    """

    ingress_interface: Annotated[str, Field(description="Interface receiving relay traffic")]
    pivots: Annotated[list[PivotConfig], Field(description="Routing pivots (VRFs)")]

    @field_validator("ingress_interface")
    @classmethod
    def validate_interface_format(cls, v: str) -> str:
        """Validate interface name format."""
        return _validate_interface_name(v)

    @model_validator(mode="after")
    def validate_relay_config(self) -> RelayConfig:
        """Cross-reference validation across entire relay configuration."""
        # Ensure at least one pivot
        if not self.pivots:
            raise ValueError("At least one pivot is required")

        # Check unique egress interfaces
        egress_ifaces = [p.egress_interface for p in self.pivots]
        if len(egress_ifaces) != len(set(egress_ifaces)):
            duplicates = sorted(
                {iface for iface in egress_ifaces if egress_ifaces.count(iface) > 1}
            )
            raise ValueError(f"Duplicate egress interfaces: {duplicates}")

        # Check ingress != egress
        if self.ingress_interface in egress_ifaces:
            raise ValueError(
                f"ingress_interface ({self.ingress_interface}) cannot be "
                "used as an egress_interface"
            )

        # Check no overlapping relay prefixes
        relay_prefixes = [
            target.relay_prefix for pivot in self.pivots for target in pivot.targets
        ]
        # Convert to IPv4Network for overlap detection
        relay_networks = [IPv4Network(p, strict=False) for p in relay_prefixes]
        for i, net1 in enumerate(relay_networks):
            for net2 in relay_networks[i + 1 :]:
                if net1.overlaps(net2):
                    raise ValueError(f"Overlapping relay prefixes: {net1} and {net2}")

        return self
