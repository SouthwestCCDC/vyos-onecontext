"""VXLAN and bridge configuration generator.

This module generates VyOS VXLAN tunnel and bridge interface configuration commands.
"""

from vyos_onecontext.generators.base import BaseGenerator
from vyos_onecontext.models import VxlanConfig


class VxlanGenerator(BaseGenerator):
    """Generate VyOS VXLAN and bridge configuration commands.

    Handles:
    1. VXLAN tunnel interface configuration
    2. Bridge interface configuration with members

    VyOS command structure:
    - VXLAN: set interfaces vxlan {name} vni {vni}
    - Bridge: set interfaces bridge {name} member interface {member}
    """

    def __init__(self, vxlan: VxlanConfig | None):
        """Initialize VXLAN generator.

        Args:
            vxlan: VXLAN configuration (None if VXLAN is not configured)
        """
        self.vxlan = vxlan

    def generate(self) -> list[str]:
        """Generate all VXLAN and bridge configuration commands.

        Returns:
            List of VyOS 'set' commands for VXLAN and bridge configuration
        """
        commands: list[str] = []

        # If VXLAN is not configured, return empty list
        if self.vxlan is None:
            return commands

        # Generate VXLAN tunnel commands
        commands.extend(self._generate_vxlan_tunnels())

        # Generate bridge commands
        commands.extend(self._generate_bridges())

        return commands

    def _generate_vxlan_tunnels(self) -> list[str]:
        """Generate VXLAN tunnel interface configuration.

        Returns:
            List of VyOS 'set' commands for VXLAN tunnels
        """
        commands: list[str] = []

        # Type narrowing
        if self.vxlan is None:
            return commands

        for tunnel in self.vxlan.tunnels:
            # VNI (required)
            commands.append(f"set interfaces vxlan {tunnel.name} vni {tunnel.vni}")

            # Remote VTEP address (required)
            commands.append(f"set interfaces vxlan {tunnel.name} remote {tunnel.remote}")

            # Source address (required)
            commands.append(
                f"set interfaces vxlan {tunnel.name} source-address {tunnel.source_address}"
            )

            # Description (optional)
            if tunnel.description:
                commands.append(
                    f"set interfaces vxlan {tunnel.name} description '{tunnel.description}'"
                )

        return commands

    def _generate_bridges(self) -> list[str]:
        """Generate bridge interface configuration.

        Returns:
            List of VyOS 'set' commands for bridge interfaces
        """
        commands: list[str] = []

        # Type narrowing
        if self.vxlan is None:
            return commands

        for bridge in self.vxlan.bridges:
            # Member interfaces (required, at least one)
            for member in bridge.members:
                commands.append(f"set interfaces bridge {bridge.name} member interface {member}")

            # Bridge IP address (required)
            commands.append(f"set interfaces bridge {bridge.name} address {bridge.address}")

            # Description (optional)
            if bridge.description:
                commands.append(
                    f"set interfaces bridge {bridge.name} description '{bridge.description}'"
                )

        return commands
