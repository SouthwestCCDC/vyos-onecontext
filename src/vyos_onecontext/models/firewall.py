"""Firewall configuration models."""

from ipaddress import IPv4Address, IPv4Network
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class FirewallGroups(BaseModel):
    """Firewall groups for reusable address/network/port sets.

    Groups allow defining named sets of networks, addresses, or ports that can
    be referenced in firewall rules.
    """

    network: Annotated[
        dict[str, list[str]], Field(default_factory=dict, description="Named network groups (CIDR)")
    ]
    address: Annotated[
        dict[str, list[str]],
        Field(default_factory=dict, description="Named address groups (individual IPs)"),
    ]
    port: Annotated[
        dict[str, list[int]], Field(default_factory=dict, description="Named port groups")
    ]

    @field_validator("network")
    @classmethod
    def validate_network_groups(cls, v: dict[str, list[str]]) -> dict[str, list[str]]:
        """Validate that all networks in groups are valid CIDR notation."""
        for group_name, networks in v.items():
            for network in networks:
                try:
                    IPv4Network(network, strict=False)
                except ValueError as e:
                    raise ValueError(
                        f"Invalid CIDR network '{network}' in group '{group_name}'"
                    ) from e
        return v

    @field_validator("address")
    @classmethod
    def validate_address_groups(cls, v: dict[str, list[str]]) -> dict[str, list[str]]:
        """Validate that all addresses in groups are valid IPs."""
        for group_name, addresses in v.items():
            for address in addresses:
                try:
                    IPv4Address(address)
                except ValueError as e:
                    raise ValueError(
                        f"Invalid IP address '{address}' in group '{group_name}'"
                    ) from e
        return v

    @field_validator("port")
    @classmethod
    def validate_port_groups(cls, v: dict[str, list[int]]) -> dict[str, list[int]]:
        """Validate that all ports in groups are valid port numbers."""
        for group_name, ports in v.items():
            for port in ports:
                if not 1 <= port <= 65535:
                    raise ValueError(
                        f"Invalid port {port} in group '{group_name}': must be 1-65535"
                    )
        return v


class FirewallRule(BaseModel):
    """A single firewall rule within a zone policy.

    Rules can match on various criteria including protocol, addresses, ports,
    and ICMP types.
    """

    action: Literal["accept", "drop", "reject"] = Field(description="Action to take")
    protocol: Annotated[
        Literal["tcp", "udp", "icmp", "tcp_udp"] | None,
        Field(None, description="Protocol filter"),
    ]
    source_address: Annotated[str | None, Field(None, description="Source IP or CIDR (inline)")]
    source_address_group: Annotated[
        str | None, Field(None, description="Source address group name")
    ]
    source_network_group: Annotated[
        str | None, Field(None, description="Source network group name")
    ]
    destination_address: Annotated[
        str | None, Field(None, description="Destination IP or CIDR (inline)")
    ]
    destination_address_group: Annotated[
        str | None, Field(None, description="Destination address group name")
    ]
    destination_network_group: Annotated[
        str | None, Field(None, description="Destination network group name")
    ]
    destination_port: Annotated[
        int | list[int] | None,
        Field(None, description="Destination port(s) (inline)"),
    ]
    destination_port_group: Annotated[
        str | None, Field(None, description="Destination port group name")
    ]
    icmp_type: Annotated[str | None, Field(None, description="ICMP type name (e.g., echo-request)")]
    description: Annotated[str | None, Field(None, description="Rule description")]

    @field_validator("source_address")
    @classmethod
    def validate_source_address(cls, v: str | None) -> str | None:
        """Validate that source_address is a valid IP or CIDR if provided."""
        if v is None:
            return None
        try:
            IPv4Address(v)
        except ValueError:
            try:
                IPv4Network(v, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid IP address or CIDR: {v}") from e
        return v

    @field_validator("destination_address")
    @classmethod
    def validate_destination_address(cls, v: str | None) -> str | None:
        """Validate that destination_address is a valid IP or CIDR if provided."""
        if v is None:
            return None
        try:
            IPv4Address(v)
        except ValueError:
            try:
                IPv4Network(v, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid IP address or CIDR: {v}") from e
        return v

    @field_validator("destination_port")
    @classmethod
    def validate_destination_port(cls, v: int | list[int] | None) -> int | list[int] | None:
        """Validate that destination port(s) are valid."""
        if v is None:
            return None
        ports = [v] if isinstance(v, int) else v
        for port in ports:
            if not 1 <= port <= 65535:
                raise ValueError(f"Invalid port {port}: must be 1-65535")
        return v

    @field_validator("icmp_type")
    @classmethod
    def validate_icmp_type(cls, v: str | None, info: Any) -> str | None:
        """Validate that icmp_type is only used with ICMP protocol."""
        if v is not None and info.data.get("protocol") != "icmp":
            raise ValueError("icmp_type can only be used with protocol='icmp'")
        return v

    @model_validator(mode="after")
    def validate_field_exclusivity(self) -> "FirewallRule":
        """Ensure only one source/destination field type is used."""
        # Check source field exclusivity
        source_fields = [
            self.source_address,
            self.source_address_group,
            self.source_network_group,
        ]
        source_count = sum(1 for field in source_fields if field is not None)
        if source_count > 1:
            raise ValueError(
                "Only one of source_address, source_address_group, or "
                "source_network_group may be specified"
            )

        # Check destination address field exclusivity
        dest_address_fields = [
            self.destination_address,
            self.destination_address_group,
            self.destination_network_group,
        ]
        dest_address_count = sum(1 for field in dest_address_fields if field is not None)
        if dest_address_count > 1:
            raise ValueError(
                "Only one of destination_address, destination_address_group, or "
                "destination_network_group may be specified"
            )

        # Check destination port field exclusivity
        dest_port_fields = [self.destination_port, self.destination_port_group]
        dest_port_count = sum(1 for field in dest_port_fields if field is not None)
        if dest_port_count > 1:
            raise ValueError(
                "Only one of destination_port or destination_port_group may be specified"
            )

        return self


class FirewallPolicy(BaseModel):
    """Firewall policy for traffic between two zones.

    Defines the ruleset that applies when traffic flows from one zone to another.
    """

    model_config = ConfigDict(populate_by_name=True)

    from_zone: Annotated[str, Field(alias="from", description="Source zone name")]
    to_zone: Annotated[str, Field(alias="to", description="Destination zone name")]
    rules: list[FirewallRule] = Field(description="List of rules for this zone pair")


class FirewallZone(BaseModel):
    """Firewall zone definition.

    Groups interfaces by security level and defines default action for traffic.
    Note: default_action cannot be 'accept' for security reasons (enforced by Literal type).
    """

    name: str = Field(description="Zone name")
    interfaces: list[str] = Field(description="Interfaces belonging to this zone")
    default_action: Literal["drop", "reject"] = Field(
        description="Default action when no rules match"
    )


class FirewallConfig(BaseModel):
    """Zone-based firewall configuration.

    Contains firewall groups, zone definitions, and inter-zone policies.
    """

    groups: Annotated[
        FirewallGroups, Field(default_factory=FirewallGroups, description="Firewall groups")
    ]
    zones: dict[str, FirewallZone] = Field(default_factory=dict, description="Zone definitions")
    policies: list[FirewallPolicy] = Field(default_factory=list, description="Inter-zone policies")

    @field_validator("zones")
    @classmethod
    def validate_zones(cls, v: dict[str, FirewallZone]) -> dict[str, FirewallZone]:
        """Ensure zone names in dict match the zone.name field."""
        new_zones: dict[str, FirewallZone] = {}
        for zone_name, zone in v.items():
            # Allow either dict key or zone.name field, but they should match if both present
            if zone.name != zone_name:
                # Create a copy with updated name instead of mutating
                new_zones[zone_name] = zone.model_copy(update={"name": zone_name})
            else:
                new_zones[zone_name] = zone
        return new_zones

    @model_validator(mode="after")
    def validate_referential_integrity(self) -> "FirewallConfig":
        """Validate that policies and rules reference existing zones and groups."""
        # Check that policy zones exist
        for policy in self.policies:
            if policy.from_zone not in self.zones:
                raise ValueError(f"Policy references non-existent from_zone: '{policy.from_zone}'")
            if policy.to_zone not in self.zones:
                raise ValueError(f"Policy references non-existent to_zone: '{policy.to_zone}'")

            # Check that rules reference existing groups
            for rule in policy.rules:
                if (
                    rule.source_address_group is not None
                    and rule.source_address_group not in self.groups.address
                ):
                    raise ValueError(
                        f"Rule references non-existent source_address_group: "
                        f"'{rule.source_address_group}'"
                    )
                if (
                    rule.source_network_group is not None
                    and rule.source_network_group not in self.groups.network
                ):
                    raise ValueError(
                        f"Rule references non-existent source_network_group: "
                        f"'{rule.source_network_group}'"
                    )
                if (
                    rule.destination_address_group is not None
                    and rule.destination_address_group not in self.groups.address
                ):
                    raise ValueError(
                        f"Rule references non-existent destination_address_group: "
                        f"'{rule.destination_address_group}'"
                    )
                if (
                    rule.destination_network_group is not None
                    and rule.destination_network_group not in self.groups.network
                ):
                    raise ValueError(
                        f"Rule references non-existent destination_network_group: "
                        f"'{rule.destination_network_group}'"
                    )
                if (
                    rule.destination_port_group is not None
                    and rule.destination_port_group not in self.groups.port
                ):
                    raise ValueError(
                        f"Rule references non-existent destination_port_group: "
                        f"'{rule.destination_port_group}'"
                    )

        return self
