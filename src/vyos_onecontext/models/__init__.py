"""Pydantic models for VyOS contextualization.

This module provides data models for parsing and validating OpenNebula context
variables and generating VyOS configuration.
"""

from vyos_onecontext.models.config import OnecontextMode, RouterConfig
from vyos_onecontext.models.dhcp import DhcpConfig, DhcpPool, DhcpReservation
from vyos_onecontext.models.firewall import (
    FirewallConfig,
    FirewallGroups,
    FirewallPolicy,
    FirewallRule,
    FirewallZone,
)
from vyos_onecontext.models.interface import AliasConfig, InterfaceConfig
from vyos_onecontext.models.nat import (
    BinatRule,
    DestinationNatRule,
    NatConfig,
    SourceNatRule,
)
from vyos_onecontext.models.routing import (
    OspfConfig,
    OspfDefaultInformation,
    OspfInterface,
    RoutesConfig,
    StaticRoute,
)
from vyos_onecontext.models.system import ConntrackConfig, ConntrackTimeoutRule

__all__ = [
    # config
    "OnecontextMode",
    "RouterConfig",
    # dhcp
    "DhcpConfig",
    "DhcpPool",
    "DhcpReservation",
    # firewall
    "FirewallConfig",
    "FirewallGroups",
    "FirewallPolicy",
    "FirewallRule",
    "FirewallZone",
    # interface
    "AliasConfig",
    "InterfaceConfig",
    # nat
    "BinatRule",
    "DestinationNatRule",
    "NatConfig",
    "SourceNatRule",
    # routing
    "OspfConfig",
    "OspfDefaultInformation",
    "OspfInterface",
    "RoutesConfig",
    "StaticRoute",
    # system
    "ConntrackConfig",
    "ConntrackTimeoutRule",
]
