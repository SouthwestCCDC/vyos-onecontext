"""Top-level router configuration models."""

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field, model_validator

from vyos_onecontext.models.dhcp import DhcpConfig
from vyos_onecontext.models.firewall import FirewallConfig
from vyos_onecontext.models.interface import AliasConfig, InterfaceConfig
from vyos_onecontext.models.nat import NatConfig
from vyos_onecontext.models.routing import OspfConfig, RoutesConfig


class OnecontextMode(str, Enum):
    """Onecontext save behavior mode.

    Controls how the configuration is saved after contextualization.
    """

    STATELESS = "stateless"
    """Don't save. Regenerate fresh every boot. (Recommended)"""

    SAVE = "save"
    """Save after commit. Still run onecontext on future boots.
    WARNING: No consistency guarantees - next boot starts from saved state."""

    FREEZE = "freeze"
    """Save and disable onecontext hook. Future boots use saved config.
    Use for handoff to manual management."""


class RouterConfig(BaseModel):
    """Complete router configuration.

    Combines all configuration features into a single top-level model that
    represents the entire router state.
    """

    # Identity
    hostname: Annotated[str | None, Field(None, description="System hostname")]
    ssh_public_key: Annotated[str | None, Field(None, description="SSH public key for vyos user")]

    # Operational mode
    onecontext_mode: Annotated[
        OnecontextMode,
        Field(OnecontextMode.STATELESS, description="Save behavior mode"),
    ]

    # Network interfaces
    interfaces: list[InterfaceConfig] = Field(
        default_factory=list, description="Network interface configurations"
    )
    aliases: list[AliasConfig] = Field(
        default_factory=list, description="NIC alias configurations (secondary IPs)"
    )

    # Routing
    routes: Annotated[
        RoutesConfig | None, Field(None, description="Static routing configuration")
    ]
    ospf: Annotated[OspfConfig | None, Field(None, description="OSPF dynamic routing")]

    # Services
    dhcp: Annotated[DhcpConfig | None, Field(None, description="DHCP server configuration")]

    # NAT
    nat: Annotated[NatConfig | None, Field(None, description="NAT configuration")]

    # Firewall
    firewall: Annotated[
        FirewallConfig | None, Field(None, description="Zone-based firewall configuration")
    ]

    # Escape hatches
    start_config: Annotated[
        str | None,
        Field(None, description="Raw VyOS commands executed within configuration transaction"),
    ]
    start_script: Annotated[
        str | None, Field(None, description="Shell script executed after VyOS config commit")
    ]

    @model_validator(mode="after")
    def validate_nat_interface_references(self) -> "RouterConfig":
        """Validate that NAT rules reference existing interfaces."""
        if self.nat is None:
            return self

        # Build set of interface names
        interface_names = {iface.name for iface in self.interfaces}

        # Check source NAT rules
        for src_rule in self.nat.source:
            if src_rule.outbound_interface not in interface_names:
                raise ValueError(
                    f"Source NAT rule references non-existent outbound_interface: "
                    f"'{src_rule.outbound_interface}'"
                )

        # Check destination NAT rules
        for dst_rule in self.nat.destination:
            if dst_rule.inbound_interface not in interface_names:
                raise ValueError(
                    f"Destination NAT rule references non-existent inbound_interface: "
                    f"'{dst_rule.inbound_interface}'"
                )

        # Check binat rules
        for binat_rule in self.nat.binat:
            if binat_rule.interface not in interface_names:
                raise ValueError(
                    f"Binat rule references non-existent interface: '{binat_rule.interface}'"
                )

        return self

    @model_validator(mode="after")
    def validate_binat_external_addresses(self) -> "RouterConfig":
        """Validate that binat external_address exists as a configured IP on the interface."""
        if self.nat is None:
            return self

        # Build map of interface name -> set of IPs (primary + aliases)
        interface_ips: dict[str, set[str]] = {}

        # Add primary interface IPs
        for iface in self.interfaces:
            interface_ips.setdefault(iface.name, set()).add(str(iface.ip))

        # Add alias IPs
        for alias in self.aliases:
            interface_ips.setdefault(alias.interface, set()).add(str(alias.ip))

        # Check binat rules
        for binat_rule in self.nat.binat:
            external_ip = str(binat_rule.external_address)
            interface = binat_rule.interface

            if interface not in interface_ips:
                raise ValueError(
                    f"Binat rule external_address '{external_ip}' references "
                    f"non-existent interface: '{interface}'"
                )

            if external_ip not in interface_ips[interface]:
                raise ValueError(
                    f"Binat rule external_address '{external_ip}' is not configured "
                    f"on interface '{interface}' (must be primary IP or alias)"
                )

        return self

    @model_validator(mode="after")
    def validate_dhcp_pool_interfaces(self) -> "RouterConfig":
        """Validate that DHCP pool interfaces reference existing interfaces."""
        if self.dhcp is None:
            return self

        interface_names = {iface.name for iface in self.interfaces}

        for pool in self.dhcp.pools:
            if pool.interface not in interface_names:
                raise ValueError(
                    f"DHCP pool references non-existent interface: '{pool.interface}'"
                )

        for reservation in self.dhcp.reservations:
            if reservation.interface not in interface_names:
                raise ValueError(
                    f"DHCP reservation references non-existent interface: '{reservation.interface}'"
                )

        return self

    @model_validator(mode="after")
    def validate_firewall_zone_interfaces(self) -> "RouterConfig":
        """Validate that firewall zone interfaces reference existing interfaces."""
        if self.firewall is None:
            return self

        interface_names = {iface.name for iface in self.interfaces}

        for zone_name, zone in self.firewall.zones.items():
            for interface in zone.interfaces:
                if interface not in interface_names:
                    raise ValueError(
                        f"Firewall zone '{zone_name}' references "
                        f"non-existent interface: '{interface}'"
                    )

        return self

    @model_validator(mode="after")
    def validate_ospf_interfaces(self) -> "RouterConfig":
        """Validate that OSPF interfaces reference existing interfaces."""
        if self.ospf is None:
            return self

        interface_names = {iface.name for iface in self.interfaces}

        for ospf_iface in self.ospf.interfaces:
            if ospf_iface.name not in interface_names:
                raise ValueError(
                    f"OSPF configuration references non-existent interface: '{ospf_iface.name}'"
                )

        return self

    @model_validator(mode="after")
    def validate_static_route_interfaces(self) -> "RouterConfig":
        """Validate that static routes reference existing interfaces."""
        if self.routes is None:
            return self

        interface_names = {iface.name for iface in self.interfaces}

        for route in self.routes.static:
            if route.interface not in interface_names:
                raise ValueError(
                    f"Static route to '{route.destination}' references "
                    f"non-existent interface: '{route.interface}'"
                )

        return self

    @model_validator(mode="after")
    def validate_alias_parent_interfaces(self) -> "RouterConfig":
        """Validate that alias parent interfaces exist."""
        interface_names = {iface.name for iface in self.interfaces}

        for alias in self.aliases:
            if alias.interface not in interface_names:
                raise ValueError(
                    f"Alias IP '{alias.ip}' references non-existent parent interface: "
                    f"'{alias.interface}'"
                )

        return self
