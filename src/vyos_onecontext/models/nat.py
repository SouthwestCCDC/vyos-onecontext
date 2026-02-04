"""NAT configuration models."""

from ipaddress import IPv4Address, IPv4Network
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class SourceNatRule(BaseModel):
    """Source NAT rule for outbound traffic.

    Used for masquerading (dynamic SNAT) or static source NAT.
    """

    outbound_interface: str = Field(description="Egress interface")
    source_address: Annotated[
        str | None, Field(None, description="Source network to NAT (CIDR notation)")
    ]
    translation: Annotated[
        Literal["masquerade"] | None,
        Field(None, description="Use masquerade for dynamic SNAT"),
    ]
    translation_address: Annotated[
        str | None, Field(None, description="Static SNAT address or range")
    ]
    address_mapping: Annotated[
        Literal["random", "persistent"] | None,
        Field(None, description="Address mapping mode for translation address pools"),
    ]
    description: Annotated[str | None, Field(None, description="Rule description")]

    @field_validator("source_address")
    @classmethod
    def validate_source_address(cls, v: str | None) -> str | None:
        """Validate that source_address is a valid CIDR network if provided."""
        if v is None:
            return None

        try:
            IPv4Network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR network: {v}") from e
        return v

    @field_validator("translation_address")
    @classmethod
    def validate_translation_address(cls, v: str | None, info: Any) -> str | None:
        """Validate translation_address and ensure mutual exclusivity with translation."""
        if v is None:
            return None

        # Check if it's an IP address or range
        # VyOS supports ranges like "10.0.1.10-10.0.1.20"
        if "-" in v:
            # Range format
            parts = v.split("-")
            if len(parts) != 2:
                raise ValueError("Invalid IP range format")
            try:
                start_ip = IPv4Address(parts[0].strip())
                end_ip = IPv4Address(parts[1].strip())
            except ValueError as e:
                raise ValueError("Invalid IP addresses in range") from e

            # Check order after we know both IPs are valid
            if end_ip < start_ip:
                raise ValueError("Invalid IP range: end address must be >= start address")
        else:
            # Single IP or CIDR
            try:
                IPv4Address(v)
            except ValueError:
                # Try as CIDR
                try:
                    IPv4Network(v, strict=False)
                except ValueError as e:
                    raise ValueError("Invalid IP address or CIDR") from e

        return v

    @model_validator(mode="after")
    def validate_translation_exclusivity(self) -> "SourceNatRule":
        """Ensure exactly one of translation or translation_address is set."""
        has_translation = self.translation is not None
        has_address = self.translation_address is not None

        if has_translation and has_address:
            raise ValueError("Cannot specify both 'translation' and 'translation_address'")
        if not has_translation and not has_address:
            raise ValueError("Must specify either 'translation' or 'translation_address'")
        
        # Validate address_mapping only used with translation_address
        if self.address_mapping is not None and has_translation:
            raise ValueError(
                "address_mapping can only be used with translation_address (pools), "
                "not with translation='masquerade'"
            )
        return self


class DestinationNatRule(BaseModel):
    """Destination NAT rule for inbound traffic.

    Used for port forwarding and destination address translation.
    """

    inbound_interface: str = Field(description="Ingress interface")
    protocol: Annotated[
        Literal["tcp", "udp", "tcp_udp", "icmp"] | None,
        Field(None, description="Protocol filter"),
    ]
    destination_address: Annotated[
        IPv4Address | None, Field(None, description="Original destination (for 1:1 NAT)")
    ]
    destination_port: Annotated[
        int | None,
        Field(None, ge=1, le=65535, description="Original destination port"),
    ]
    translation_address: Annotated[IPv4Address, Field(description="New destination address")]
    translation_port: Annotated[
        int | None, Field(None, ge=1, le=65535, description="New destination port")
    ]
    description: Annotated[str | None, Field(None, description="Rule description")]

    @field_validator("destination_port")
    @classmethod
    def validate_destination_port(cls, v: int | None, info: Any) -> int | None:
        """Validate that destination_port is not used with ICMP protocol."""
        if v is not None and info.data.get("protocol") == "icmp":
            raise ValueError("destination_port is not valid for ICMP protocol")
        return v


class BinatRule(BaseModel):
    """Bidirectional 1:1 NAT rule.

    Creates both source and destination NAT rules for full bidirectional
    translation between an external and internal address.
    """

    external_address: Annotated[
        IPv4Address, Field(description="External/public IP (must be alias on interface)")
    ]
    internal_address: Annotated[IPv4Address, Field(description="Internal IP to map to")]
    interface: str = Field(description="Interface where external IP is assigned")
    description: Annotated[str | None, Field(None, description="Rule description")]


class NatConfig(BaseModel):
    """NAT configuration.

    Contains source NAT (masquerading), destination NAT (port forwarding), and
    bidirectional 1:1 NAT rules.
    """

    source: list[SourceNatRule] = Field(default_factory=list, description="Source NAT rules")
    destination: list[DestinationNatRule] = Field(
        default_factory=list, description="Destination NAT rules"
    )
    binat: list[BinatRule] = Field(default_factory=list, description="Bidirectional 1:1 NAT rules")
