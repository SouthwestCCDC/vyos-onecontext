"""Routing configuration generator (static routes, default gateway)."""

from vyos_onecontext.generators.base import BaseGenerator
from vyos_onecontext.generators.utils import natural_sort_key
from vyos_onecontext.models import InterfaceConfig


class RoutingGenerator(BaseGenerator):
    """Generate VyOS routing configuration commands.

    Handles default gateway selection and static route generation.
    """

    def __init__(self, interfaces: list[InterfaceConfig]):
        """Initialize routing generator.

        Args:
            interfaces: List of interface configurations
        """
        self.interfaces = interfaces

    def generate(self) -> list[str]:
        """Generate routing configuration commands.

        Generates commands for:
        - Default gateway (automatically selected from interfaces)

        The default gateway is selected from the lowest-numbered interface
        where:
        - Interface has a gateway configured
        - Gateway IP differs from interface's own IP (router is not the gateway)
        - Interface is NOT in management VRF

        Returns:
            List of VyOS 'set' commands for routing configuration
        """
        commands: list[str] = []

        # Select default gateway
        default_gateway = self._select_default_gateway()
        if default_gateway:
            commands.append(f"set protocols static route 0.0.0.0/0 next-hop {default_gateway}")

        return commands

    def _select_default_gateway(self) -> str | None:
        """Select the default gateway from available interfaces.

        Selection algorithm:
        - Find the lowest-numbered interface (by name sort order) where:
          1. Interface has a gateway configured (ETHx_GATEWAY)
          2. Gateway IP differs from interface's own IP (router is not the gateway)
          3. Interface is NOT in management VRF (ETHx_VROUTER_MANAGEMENT is not YES)

        Returns:
            Gateway IP address as string, or None if no valid gateway found
        """
        # Sort interfaces by numeric portion of name (eth0 before eth1 before eth10)
        sorted_interfaces = sorted(self.interfaces, key=natural_sort_key)

        for iface in sorted_interfaces:
            # Skip interfaces without a gateway
            if iface.gateway is None:
                continue

            # Skip if gateway equals interface IP (router IS the gateway for that network)
            if iface.gateway == iface.ip:
                continue

            # Skip management VRF interfaces
            if iface.management:
                continue

            # This interface has a valid gateway
            return str(iface.gateway)

        # No valid gateway found
        return None
