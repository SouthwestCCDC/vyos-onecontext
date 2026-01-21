"""VyOS command generators.

This module provides generators that convert parsed configuration models into
VyOS CLI commands. Each generator is responsible for a specific aspect of the
configuration (interfaces, routing, NAT, etc.).
"""

from vyos_onecontext.generators.base import BaseGenerator
from vyos_onecontext.generators.dhcp import DhcpGenerator
from vyos_onecontext.generators.firewall import FirewallGenerator
from vyos_onecontext.generators.interface import InterfaceGenerator
from vyos_onecontext.generators.nat import NatGenerator
from vyos_onecontext.generators.ospf import OspfGenerator
from vyos_onecontext.generators.routing import RoutingGenerator, StaticRoutesGenerator
from vyos_onecontext.generators.service import SshServiceGenerator
from vyos_onecontext.generators.system import HostnameGenerator, SshKeyGenerator
from vyos_onecontext.generators.vrf import VRF_NAME, VRF_TABLE_ID, VrfGenerator
from vyos_onecontext.models import RouterConfig


def generate_config(config: RouterConfig) -> list[str]:
    """Generate all VyOS commands from a RouterConfig.

    Generates commands in the correct order for VyOS commit:
    1. System configuration (hostname, SSH keys)
    2. Network interfaces
    3. Routing (default gateway, static routes)
    4. ... (other generators will be added in later phases)

    Args:
        config: Complete router configuration

    Returns:
        List of VyOS 'set' commands ready for execution
    """
    commands: list[str] = []

    # System config first
    commands.extend(HostnameGenerator(config.hostname).generate())
    commands.extend(SshKeyGenerator(config.ssh_public_key).generate())

    # Interfaces
    commands.extend(InterfaceGenerator(config.interfaces, config.aliases).generate())

    # Routing (default gateway selection for non-management interfaces)
    commands.extend(RoutingGenerator(config.interfaces).generate())

    # VRF configuration (management VRF) - must come BEFORE static routes
    # since routes can reference VRFs
    commands.extend(VrfGenerator(config.interfaces).generate())

    # Static routes (ROUTES_JSON) - must come AFTER VRF since routes can reference VRFs
    commands.extend(StaticRoutesGenerator(config.routes).generate())

    # Services (SSH VRF binding)
    commands.extend(SshServiceGenerator(config.interfaces).generate())

    # OSPF dynamic routing
    commands.extend(OspfGenerator(config.ospf).generate())

    # DHCP server
    commands.extend(DhcpGenerator(config.dhcp).generate())

    # NAT (source, destination, binat)
    commands.extend(NatGenerator(config.nat).generate())

    # Firewall (groups, zones, global state policy, inter-zone policies)
    commands.extend(FirewallGenerator(config.firewall).generate())

    # Future generators will be added here in later phases:
    # - DNS service (recursive resolver, forwarding)
    # - Custom config (START_CONFIG)

    return commands


__all__ = [
    "BaseGenerator",
    "DhcpGenerator",
    "FirewallGenerator",
    "HostnameGenerator",
    "InterfaceGenerator",
    "NatGenerator",
    "OspfGenerator",
    "RoutingGenerator",
    "SshKeyGenerator",
    "SshServiceGenerator",
    "StaticRoutesGenerator",
    "VrfGenerator",
    "VRF_NAME",
    "VRF_TABLE_ID",
    "generate_config",
]
