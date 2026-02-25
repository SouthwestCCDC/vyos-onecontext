"""VXLAN configuration models."""

import re
from ipaddress import IPv4Address
from typing import Annotated

from pydantic import BaseModel, Field, field_validator, model_validator


class VxlanTunnelConfig(BaseModel):
    """Configuration for a VXLAN tunnel interface.

    VXLAN tunnels provide Layer 2 connectivity over Layer 3 networks, commonly
    used for stretching broadcast domains across multiple sites.
    """

    name: str = Field(description="VXLAN interface name (e.g., vxlan0)")
    vni: Annotated[int, Field(ge=1, le=16777215, description="VXLAN Network Identifier (VNI)")]
    remote: Annotated[IPv4Address, Field(description="Remote VTEP IP address")]
    source_address: Annotated[IPv4Address, Field(description="Local VTEP IP (source-address)")]
    description: Annotated[str, Field("", description="Interface description")]

    @field_validator("name")
    @classmethod
    def validate_vxlan_name(cls, v: str) -> str:
        """Validate VXLAN interface name follows expected pattern.

        Args:
            v: VXLAN interface name to validate

        Returns:
            The validated VXLAN interface name

        Raises:
            ValueError: If VXLAN interface name is invalid
        """
        pattern = re.compile(r"^vxlan\d+$")
        if not pattern.fullmatch(v):
            raise ValueError(
                f"Invalid VXLAN interface name '{v}' (expected vxlanN format, e.g., vxlan0, vxlan1)"
            )
        return v


class BridgeConfig(BaseModel):
    """Configuration for a bridge interface.

    Bridges combine multiple interfaces (physical ethernet and/or VXLAN tunnels)
    into a single Layer 2 broadcast domain.
    """

    name: str = Field(description="Bridge interface name (e.g., br0)")
    address: Annotated[
        str, Field(description="Bridge IP address in CIDR notation (e.g., 172.22.1.1/16)")
    ]
    members: list[str] = Field(description="Interface names to add to bridge (ethN or vxlanN)")
    description: Annotated[str, Field("", description="Bridge description")]

    @field_validator("name")
    @classmethod
    def validate_bridge_name(cls, v: str) -> str:
        """Validate bridge interface name follows VyOS conventions.

        Args:
            v: Bridge interface name to validate

        Returns:
            The validated bridge interface name

        Raises:
            ValueError: If bridge interface name is invalid
        """
        pattern = re.compile(r"^br\d+$")
        if not pattern.fullmatch(v):
            raise ValueError(
                f"Invalid bridge interface name '{v}' (expected brN format, e.g., br0, br1)"
            )
        return v

    @field_validator("address")
    @classmethod
    def validate_address(cls, v: str) -> str:
        """Validate that address is in valid CIDR notation.

        Args:
            v: Address in CIDR notation

        Returns:
            The validated address

        Raises:
            ValueError: If address is invalid or missing prefix
        """
        from ipaddress import IPv4Network

        # Require explicit CIDR notation (must contain '/')
        if "/" not in v:
            raise ValueError(f"Invalid CIDR address: {v} (must include prefix length, e.g., /24)")

        try:
            IPv4Network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR address: {v}") from e
        return v

    @field_validator("members")
    @classmethod
    def validate_members(cls, v: list[str]) -> list[str]:
        """Validate that members list is not empty and names follow expected patterns.

        Args:
            v: List of member interface names

        Returns:
            The validated members list

        Raises:
            ValueError: If members list is invalid
        """
        if not v:
            raise ValueError("Bridge must have at least one member interface")

        # Validate each member name follows ethN or vxlanN pattern
        eth_pattern = re.compile(r"^eth\d+$")
        vxlan_pattern = re.compile(r"^vxlan\d+$")

        for member in v:
            if not (eth_pattern.fullmatch(member) or vxlan_pattern.fullmatch(member)):
                raise ValueError(
                    f"Invalid bridge member interface name '{member}' "
                    f"(expected ethN or vxlanN format)"
                )

        # Check for duplicates
        if len(v) != len(set(v)):
            raise ValueError("Bridge members list contains duplicate interfaces")

        return v


class VxlanConfig(BaseModel):
    """VXLAN and bridge configuration.

    Combines VXLAN tunnel definitions with bridge configurations to enable
    stretched Layer 2 networks across multiple sites.
    """

    tunnels: list[VxlanTunnelConfig] = Field(
        default_factory=list, description="VXLAN tunnel configurations"
    )
    bridges: list[BridgeConfig] = Field(default_factory=list, description="Bridge configurations")

    @model_validator(mode="after")
    def validate_tunnel_names_unique(self) -> "VxlanConfig":
        """Ensure tunnel names are unique."""
        names = [tunnel.name for tunnel in self.tunnels]
        if len(names) != len(set(names)):
            raise ValueError("VXLAN tunnel names must be unique")
        return self

    @model_validator(mode="after")
    def validate_bridge_names_unique(self) -> "VxlanConfig":
        """Ensure bridge names are unique."""
        names = [bridge.name for bridge in self.bridges]
        if len(names) != len(set(names)):
            raise ValueError("Bridge names must be unique")
        return self

    @model_validator(mode="after")
    def validate_bridge_vxlan_references(self) -> "VxlanConfig":
        """Ensure bridge members referencing vxlan interfaces point to defined tunnels."""
        # Build set of defined tunnel names
        tunnel_names = {tunnel.name for tunnel in self.tunnels}

        # Check each bridge member
        for bridge in self.bridges:
            for member in bridge.members:
                # If member is a vxlan interface, it must be defined in tunnels
                if member.startswith("vxlan") and member not in tunnel_names:
                    raise ValueError(
                        f"Bridge '{bridge.name}' references undefined VXLAN interface '{member}'"
                    )

        return self
