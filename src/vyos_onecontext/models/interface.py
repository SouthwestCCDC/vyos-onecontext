"""Interface configuration models."""

from ipaddress import IPv4Address
from typing import Annotated

from pydantic import BaseModel, Field, field_validator


class InterfaceConfig(BaseModel):
    """Configuration for a network interface.

    Represents basic interface settings including IP address, netmask, gateway,
    MTU, and management VRF placement.
    """

    name: str = Field(description="Interface name (e.g., eth0)")
    ip: Annotated[IPv4Address, Field(description="IPv4 address for interface")]
    mask: Annotated[str, Field(description="Dotted-decimal netmask (e.g., 255.255.255.0)")]
    gateway: Annotated[IPv4Address | None, Field(None, description="Default gateway")]
    dns: Annotated[IPv4Address | None, Field(None, description="DNS server")]
    mtu: Annotated[int | None, Field(None, ge=68, le=9000, description="Interface MTU")]
    management: Annotated[
        bool, Field(False, description="Place interface in management VRF")
    ]

    @field_validator("mask")
    @classmethod
    def validate_netmask(cls, v: str) -> str:
        """Validate that mask is a valid dotted-decimal netmask."""
        parts = v.split(".")
        if len(parts) != 4:
            raise ValueError("Netmask must be in dotted-decimal format (e.g., 255.255.255.0)")

        try:
            octets = [int(part) for part in parts]
        except ValueError as e:
            raise ValueError("Netmask octets must be integers") from e

        if not all(0 <= octet <= 255 for octet in octets):
            raise ValueError("Netmask octets must be between 0 and 255")

        # Convert to binary and validate it's a valid netmask (contiguous 1s followed by 0s)
        bits = "".join(f"{octet:08b}" for octet in octets)
        if "01" in bits:
            raise ValueError("Invalid netmask: must be contiguous 1 bits followed by 0 bits")

        return v

    def to_prefix_length(self) -> int:
        """Convert dotted-decimal netmask to CIDR prefix length."""
        octets = [int(part) for part in self.mask.split(".")]
        bits = "".join(f"{octet:08b}" for octet in octets)
        return bits.count("1")

    def to_cidr(self) -> str:
        """Return interface address in CIDR notation."""
        return f"{self.ip}/{self.to_prefix_length()}"


class AliasConfig(BaseModel):
    """Configuration for a secondary IP address (NIC alias).

    NIC aliases provide additional IP addresses on the same interface, commonly
    used for 1:1 NAT scenarios where additional public IPs are needed.
    """

    interface: str = Field(description="Parent interface name (e.g., eth0)")
    ip: Annotated[IPv4Address, Field(description="IPv4 address for alias")]
    mask: Annotated[
        str | None, Field(None, description="Dotted-decimal netmask (may be empty due to ONE bug)")
    ]

    @field_validator("mask")
    @classmethod
    def validate_netmask(cls, v: str | None) -> str | None:
        """Validate that mask is a valid dotted-decimal netmask if provided."""
        if v is None or v == "":
            return None

        parts = v.split(".")
        if len(parts) != 4:
            raise ValueError("Netmask must be in dotted-decimal format (e.g., 255.255.255.0)")

        try:
            octets = [int(part) for part in parts]
        except ValueError as e:
            raise ValueError("Netmask octets must be integers") from e

        if not all(0 <= octet <= 255 for octet in octets):
            raise ValueError("Netmask octets must be between 0 and 255")

        # Convert to binary and validate it's a valid netmask
        bits = "".join(f"{octet:08b}" for octet in octets)
        if "01" in bits:
            raise ValueError("Invalid netmask: must be contiguous 1 bits followed by 0 bits")

        return v

    def to_prefix_length(self, fallback_mask: str) -> int:
        """Convert dotted-decimal netmask to CIDR prefix length.

        Args:
            fallback_mask: Netmask to use if alias mask is None (from parent interface)

        Returns:
            CIDR prefix length
        """
        mask = self.mask if self.mask is not None else fallback_mask
        octets = [int(part) for part in mask.split(".")]
        bits = "".join(f"{octet:08b}" for octet in octets)
        return bits.count("1")

    def to_cidr(self, fallback_mask: str) -> str:
        """Return alias address in CIDR notation.

        Args:
            fallback_mask: Netmask to use if alias mask is None (from parent interface)

        Returns:
            Address in CIDR format (e.g., "10.0.1.2/24")
        """
        return f"{self.ip}/{self.to_prefix_length(fallback_mask)}"
