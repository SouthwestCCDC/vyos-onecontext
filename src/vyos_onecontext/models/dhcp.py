"""DHCP server configuration models."""

from ipaddress import IPv4Address, IPv4Network
from typing import Annotated, Any

from pydantic import BaseModel, Field, field_validator


class DhcpPool(BaseModel):
    """DHCP pool configuration.

    Defines a range of IP addresses to lease to DHCP clients, along with
    network options like gateway and DNS servers.
    """

    interface: str = Field(description="Interface for this pool")
    subnet: Annotated[
        str | None,
        Field(None, description="Subnet in CIDR notation (auto-derived from interface if not set)"),
    ]
    range_start: Annotated[IPv4Address, Field(description="First IP in range")]
    range_end: Annotated[IPv4Address, Field(description="Last IP in range")]
    gateway: Annotated[IPv4Address, Field(description="Default gateway for clients")]
    dns: list[IPv4Address] = Field(description="DNS servers for clients")
    lease_time: Annotated[int | None, Field(None, ge=60, description="Lease time in seconds")]
    domain: Annotated[str | None, Field(None, description="Domain name for clients")]

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, v: str | None) -> str | None:
        """Validate that subnet is a valid CIDR network if provided."""
        if v is None:
            return None

        try:
            IPv4Network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR network: {v}") from e
        return v

    @field_validator("range_end")
    @classmethod
    def validate_range_order(cls, v: IPv4Address, info: Any) -> IPv4Address:
        """Validate that range_end is greater than or equal to range_start."""
        if "range_start" in info.data and v < info.data["range_start"]:
            raise ValueError("range_end must be greater than or equal to range_start")
        return v


class DhcpReservation(BaseModel):
    """Static DHCP reservation.

    Maps a MAC address to a specific IP address, ensuring the same client
    always receives the same IP.
    """

    interface: str = Field(description="Interface for reservation")
    mac: str = Field(description="Client MAC address")
    ip: Annotated[IPv4Address, Field(description="Reserved IP address")]
    hostname: Annotated[str | None, Field(None, description="Hostname for client")]

    @field_validator("mac")
    @classmethod
    def validate_mac(cls, v: str) -> str:
        """Validate that MAC address is in valid format."""
        # Accept formats: 00:11:22:33:44:55, 00-11-22-33-44-55, 001122334455
        v = v.lower()

        # Normalize to colon-separated format
        if "-" in v:
            v = v.replace("-", ":")
        elif len(v) == 12 and ":" not in v:
            # Insert colons for bare format
            v = ":".join(v[i : i + 2] for i in range(0, 12, 2))

        parts = v.split(":")
        if len(parts) != 6:
            raise ValueError("MAC address must have 6 octets")

        for part in parts:
            if len(part) != 2:
                raise ValueError("Each MAC address octet must be 2 hex digits")
            try:
                int(part, 16)
            except ValueError as e:
                raise ValueError("MAC address octets must be hexadecimal") from e

        return v


class DhcpConfig(BaseModel):
    """DHCP server configuration.

    Contains pools for dynamic address allocation and reservations for static
    assignments.
    """

    pools: list[DhcpPool] = Field(default_factory=list, description="DHCP pools")
    reservations: list[DhcpReservation] = Field(
        default_factory=list, description="Static DHCP reservations"
    )
