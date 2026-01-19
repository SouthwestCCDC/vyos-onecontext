"""VRF configuration generator for management VRF."""

from vyos_onecontext.generators.base import BaseGenerator
from vyos_onecontext.generators.utils import natural_sort_key
from vyos_onecontext.models import InterfaceConfig

VRF_NAME = "management"
VRF_TABLE_ID = 100


class VrfGenerator(BaseGenerator):
    """Generate VyOS VRF configuration commands.

    Creates management VRF and assigns interfaces to it based on the
    management flag in interface configuration.
    """

    def __init__(self, interfaces: list[InterfaceConfig]):
        """Initialize VRF generator.

        Args:
            interfaces: List of interface configurations
        """
        self.interfaces = interfaces

    def generate(self) -> list[str]:
        """Generate VRF configuration commands.

        Generates commands in order:
        1. Create VRF (if any management interfaces exist)
        2. Assign each management interface to VRF
        3. Generate VRF-specific default route (if applicable)

        Returns:
            List of VyOS 'set' commands for VRF configuration
        """
        # Filter to only management interfaces
        management_interfaces = [iface for iface in self.interfaces if iface.management]

        # No VRF commands if no management interfaces
        if not management_interfaces:
            return []

        commands: list[str] = []

        # 1. Create VRF with routing table
        commands.append(f"set vrf name {VRF_NAME} table {VRF_TABLE_ID}")

        # 2. Assign each management interface to the VRF
        for iface in management_interfaces:
            commands.append(f"set interfaces ethernet {iface.name} vrf {VRF_NAME}")

        # 3. Generate VRF-specific default route
        vrf_gateway = self._select_vrf_default_gateway(management_interfaces)
        if vrf_gateway:
            commands.append(
                f"set vrf name {VRF_NAME} protocols static route 0.0.0.0/0 "
                f"next-hop {vrf_gateway}"
            )

        return commands

    def _select_vrf_default_gateway(
        self, management_interfaces: list[InterfaceConfig]
    ) -> str | None:
        """Select the default gateway for the management VRF.

        Selection algorithm (same as RoutingGenerator):
        - Find the lowest-numbered interface (by name sort order) where:
          1. Interface has a gateway configured (ETHx_GATEWAY)
          2. Gateway IP differs from interface's own IP (router is not the gateway)

        Args:
            management_interfaces: List of management-flagged interface configs

        Returns:
            Gateway IP address as string, or None if no valid gateway found
        """
        # Sort interfaces by numeric portion of name (eth0 before eth1 before eth10)
        sorted_interfaces = sorted(management_interfaces, key=natural_sort_key)

        for iface in sorted_interfaces:
            # Skip interfaces without a gateway
            if iface.gateway is None:
                continue

            # Skip if gateway equals interface IP (router IS the gateway for that network)
            if iface.gateway == iface.ip:
                continue

            # This interface has a valid gateway
            return str(iface.gateway)

        # No valid gateway found
        return None
