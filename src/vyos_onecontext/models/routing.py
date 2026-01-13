"""Routing configuration models."""

from ipaddress import IPv4Address, IPv4Network
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator


class StaticRoute(BaseModel):
    """A static route entry.

    Static routes can either use a next-hop gateway or be bound directly to an
    interface (interface routes).
    """

    interface: str = Field(description="Egress interface")
    destination: Annotated[str, Field(description="Destination network in CIDR notation")]
    gateway: Annotated[IPv4Address | None, Field(None, description="Next-hop gateway")]
    distance: Annotated[int, Field(1, ge=1, le=255, description="Administrative distance")]
    vrf: Annotated[str | None, Field(None, description="VRF name")]

    @field_validator("destination")
    @classmethod
    def validate_destination(cls, v: str) -> str:
        """Validate that destination is a valid CIDR network."""
        try:
            IPv4Network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR network: {v}") from e
        return v


class RoutesConfig(BaseModel):
    """Static routing configuration.

    Contains the list of static routes to be configured.
    """

    static: list[StaticRoute] = Field(default_factory=list, description="List of static routes")


class OspfInterface(BaseModel):
    """OSPF interface configuration.

    Defines OSPF settings for a specific interface using the Sagitta interface-based
    approach.
    """

    name: str = Field(description="Interface name (e.g., eth1)")
    area: str = Field(description="OSPF area ID in dotted-decimal format (e.g., 0.0.0.0)")
    passive: Annotated[
        bool,
        Field(
            False,
            description="If true, advertise network but don't form adjacencies",
        ),
    ]
    cost: Annotated[int | None, Field(None, ge=1, le=65535, description="Interface cost metric")]

    @field_validator("area")
    @classmethod
    def validate_area(cls, v: str) -> str:
        """Validate that area is in dotted-decimal format."""
        # Area can be either dotted-decimal (e.g., 0.0.0.0) or plain integer (e.g., 0)
        # We accept both but prefer dotted-decimal
        parts = v.split(".")
        if len(parts) == 4:
            # Dotted-decimal format
            try:
                octets = [int(part) for part in parts]
            except ValueError as e:
                raise ValueError("Area ID octets must be integers") from e

            if not all(0 <= octet <= 255 for octet in octets):
                raise ValueError("Area ID octets must be between 0 and 255")
        elif len(parts) == 1:
            # Plain integer format - convert to dotted-decimal
            try:
                area_int = int(v)
            except ValueError as e:
                raise ValueError("Area ID must be dotted-decimal or integer") from e

            if not 0 <= area_int <= 4294967295:
                raise ValueError("Area ID must be between 0 and 4294967295")

            # Convert to dotted-decimal
            v = (
                f"{(area_int >> 24) & 0xFF}.{(area_int >> 16) & 0xFF}."
                f"{(area_int >> 8) & 0xFF}.{area_int & 0xFF}"
            )
        else:
            raise ValueError("Area ID must be in dotted-decimal format (e.g., 0.0.0.0) or integer")

        return v


class OspfDefaultInformation(BaseModel):
    """OSPF default route origination settings."""

    originate: bool = Field(description="Originate default route into OSPF")
    always: Annotated[
        bool,
        Field(False, description="Always originate even without default route in RIB"),
    ]
    metric: Annotated[
        int | None,
        Field(None, ge=0, le=16777214, description="Metric for originated default route"),
    ]


class OspfConfig(BaseModel):
    """OSPF dynamic routing configuration.

    Uses interface-based configuration (Sagitta best practice) rather than
    network-based configuration.
    """

    enabled: bool = Field(description="Enable OSPF")
    router_id: Annotated[IPv4Address | None, Field(None, description="OSPF router ID")]
    interfaces: list[OspfInterface] = Field(
        default_factory=list, description="OSPF interface configurations"
    )
    redistribute: Annotated[
        list[Literal["connected", "static", "kernel"]],
        Field(default_factory=list, description="Protocols to redistribute"),
    ]
    default_information: Annotated[
        OspfDefaultInformation | None,
        Field(None, description="Default route origination settings"),
    ]
