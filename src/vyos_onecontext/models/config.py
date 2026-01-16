"""Top-level router configuration models."""

import re
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field, field_validator, model_validator

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

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str | None) -> str | None:
        """Validate hostname follows RFC 1123 conventions.

        Args:
            v: Hostname to validate

        Returns:
            The validated hostname

        Raises:
            ValueError: If hostname is invalid
        """
        if v is None:
            return None

        if len(v) > 253:
            raise ValueError("Hostname too long (max 253 chars)")

        # RFC 1123 hostname pattern:
        # - Labels separated by dots
        # - Each label 1-63 chars
        # - Start/end with alphanumeric
        # - Can contain hyphens in the middle
        pattern = (
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
            r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
        )
        if not re.match(pattern, v):
            raise ValueError("Invalid hostname format (must follow RFC 1123)")

        return v

    @field_validator("ssh_public_key")
    @classmethod
    def validate_ssh_key(cls, v: str | None) -> str | None:
        """Validate SSH public key format.

        Args:
            v: SSH public key to validate

        Returns:
            The validated SSH key

        Raises:
            ValueError: If SSH key format is invalid
        """
        if v is None:
            return None

        # SSH key format: type key [comment]
        # Valid types: ssh-rsa, ssh-dss, ssh-ed25519, ecdsa-sha2-nistp256, etc.
        parts = v.strip().split(None, 2)  # Split on whitespace, max 3 parts
        if len(parts) < 2:
            raise ValueError("SSH key must have at least type and key data")

        key_type = parts[0]
        key_data = parts[1]

        # Validate key type
        valid_types = {
            "ssh-rsa",
            "ssh-dss",
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "sk-ssh-ed25519@openssh.com",
            "sk-ecdsa-sha2-nistp256@openssh.com",
        }
        if key_type not in valid_types:
            raise ValueError(f"Invalid SSH key type '{key_type}'")

        # Validate key data looks like base64
        # Base64 uses A-Z, a-z, 0-9, +, /, and = for padding (max 2 padding chars)
        if not re.match(r"^[A-Za-z0-9+/]+={0,2}$", key_data):
            raise ValueError("SSH key data must be valid base64")

        # Minimum length check for SSH key data
        # The shortest valid key is ssh-ed25519 which has 68 base64 chars
        # We use 16 as a reasonable minimum to catch obviously invalid data
        # while still allowing for potential future shorter key types
        MIN_SSH_KEY_DATA_LENGTH = 16
        if len(key_data) < MIN_SSH_KEY_DATA_LENGTH:
            raise ValueError("SSH key data is too short")

        return v

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
        Field(
            None,
            description="RAW VyOS commands executed within configuration transaction. "
            "NO VALIDATION PERFORMED. Only use with trusted input from infrastructure admins.",
        ),
    ]
    start_script: Annotated[
        str | None,
        Field(
            None,
            description="Shell script executed after VyOS config commit. "
            "NO VALIDATION PERFORMED. Only use with trusted input from infrastructure admins.",
        ),
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
