"""VyOS command generators.

This module provides generators that convert parsed configuration models into
VyOS CLI commands. Each generator is responsible for a specific aspect of the
configuration (interfaces, routing, NAT, etc.).
"""

from vyos_onecontext.generators.base import BaseGenerator
from vyos_onecontext.generators.custom import StartConfigGenerator
from vyos_onecontext.generators.dhcp import DhcpGenerator
from vyos_onecontext.generators.firewall import FirewallGenerator
from vyos_onecontext.generators.interface import InterfaceGenerator
from vyos_onecontext.generators.nat import NatGenerator
from vyos_onecontext.generators.ospf import OspfGenerator
from vyos_onecontext.generators.relay import RelayGenerator
from vyos_onecontext.generators.routing import RoutingGenerator, StaticRoutesGenerator
from vyos_onecontext.generators.service import SshServiceGenerator
from vyos_onecontext.generators.system import ConntrackGenerator, HostnameGenerator, SshKeyGenerator
from vyos_onecontext.generators.vrf import VRF_NAME, VRF_TABLE_ID, VrfGenerator
from vyos_onecontext.generators.vxlan import VxlanGenerator
from vyos_onecontext.models import RouterConfig


def generate_config(config: RouterConfig) -> list[str]:
    """Generate all VyOS commands from a RouterConfig.

    Generates commands in the correct order for VyOS commit:
    1. System configuration (hostname, SSH keys)
    2. VRF configuration (must happen BEFORE interface IP configuration)
    3. Relay VRF configuration (if RELAY_JSON present - must come BEFORE interface IP configuration)
    4. Network interfaces (IP addresses, MTU) - skips IPs for bridged interfaces
    5. VXLAN tunnels and bridges (must come AFTER interfaces exist)
    6. Relay configuration continued (if RELAY_JSON present - PBR, NAT, proxy-ARP, static routes)
    7. Routing (default gateway selection for non-management interfaces)
    8. Static routes (ROUTES_JSON; may reference VRFs)
    9. Services (SSH VRF binding)
    10. Dynamic routing (OSPF)
    11. DHCP server
    12. NAT (source, destination, binat)
    13. Firewall
    14. Conntrack timeout rules
    15. Custom start config (START_CONFIG)

    Args:
        config: Complete router configuration

    Returns:
        List of VyOS 'set' commands ready for execution
    """
    commands: list[str] = []

    # System config first
    commands.extend(HostnameGenerator(config.hostname).generate())
    commands.extend(SshKeyGenerator(config.ssh_public_key).generate())

    # VRF configuration (management VRF) - must come BEFORE interface IP configuration
    # VyOS requires VRF assignment on bare interfaces (no IPs configured yet)
    commands.extend(VrfGenerator(config.interfaces).generate())

    # Relay VRF configuration - must come BEFORE interface IP configuration
    # Creates VRFs and binds egress interfaces to them
    relay_gen = RelayGenerator(config.relay, config.interfaces)
    commands.extend(relay_gen.generate_vrf_commands())

    # Determine which interfaces are bridged (so we skip IP assignment)
    bridged_interfaces: set[str] = set()
    if config.vxlan is not None:
        for bridge in config.vxlan.bridges:
            for member in bridge.members:
                # Only ethernet interfaces should skip IP assignment
                # (vxlan interfaces never had IPs to begin with)
                if member.startswith("eth"):
                    bridged_interfaces.add(member)

    # Interfaces (IP addresses, MTU)
    # This comes AFTER VRF assignment to avoid VyOS rejection
    # Skips IP assignment for bridged interfaces
    commands.extend(
        InterfaceGenerator(config.interfaces, config.aliases, bridged_interfaces).generate()
    )

    # VXLAN tunnels and bridges
    # Must come AFTER interfaces so physical interfaces exist
    commands.extend(VxlanGenerator(config.vxlan).generate())

    # Relay configuration continued - must come AFTER interface IP configuration
    # Generates PBR, NAT, proxy-ARP, and static routes for relay
    commands.extend(relay_gen.generate_relay_commands())

    # Routing (default gateway selection for non-management interfaces)
    commands.extend(RoutingGenerator(config.interfaces).generate())

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

    # Conntrack timeout rules
    commands.extend(ConntrackGenerator(config.conntrack).generate())

    # Custom config (START_CONFIG) - executed last, before commit
    commands.extend(StartConfigGenerator(config.start_config).generate())

    # Future generators will be added here in later phases:
    # - DNS service (recursive resolver, forwarding)

    return commands


__all__ = [
    "BaseGenerator",
    "ConntrackGenerator",
    "DhcpGenerator",
    "FirewallGenerator",
    "HostnameGenerator",
    "InterfaceGenerator",
    "NatGenerator",
    "OspfGenerator",
    "RelayGenerator",
    "RoutingGenerator",
    "SshKeyGenerator",
    "SshServiceGenerator",
    "StartConfigGenerator",
    "StaticRoutesGenerator",
    "VrfGenerator",
    "VxlanGenerator",
    "VRF_NAME",
    "VRF_TABLE_ID",
    "generate_config",
]
