"""Top-level router configuration models."""

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field

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
