"""VyOS command generators.

This module provides generators that convert parsed configuration models into
VyOS CLI commands. Each generator is responsible for a specific aspect of the
configuration (interfaces, routing, NAT, etc.).
"""

from vyos_onecontext.generators.base import BaseGenerator
from vyos_onecontext.generators.interface import InterfaceGenerator
from vyos_onecontext.generators.routing import RoutingGenerator
from vyos_onecontext.generators.system import HostnameGenerator, SshKeyGenerator
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

    # Routing (default gateway selection)
    commands.extend(RoutingGenerator(config.interfaces).generate())

    # Future generators will be added here in later phases:
    # - Services (DHCP, DNS)
    # - NAT (source, destination, binat)
    # - Firewall (zones, policies, rules)
    # - Custom config (START_CONFIG)

    return commands


__all__ = [
    "BaseGenerator",
    "HostnameGenerator",
    "InterfaceGenerator",
    "RoutingGenerator",
    "SshKeyGenerator",
    "generate_config",
]
