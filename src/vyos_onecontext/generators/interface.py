"""Interface configuration generator."""

from vyos_onecontext.generators.base import BaseGenerator
from vyos_onecontext.models import AliasConfig, InterfaceConfig


class InterfaceGenerator(BaseGenerator):
    """Generate VyOS interface configuration commands."""

    def __init__(
        self,
        interfaces: list[InterfaceConfig],
        aliases: list[AliasConfig],
        bridged_interfaces: set[str] | None = None,
    ):
        """Initialize interface generator.

        Args:
            interfaces: List of interface configurations
            aliases: List of NIC alias configurations (secondary IPs)
            bridged_interfaces: Set of interface names that are bridge members
                               (IP addresses will not be assigned to these interfaces)
        """
        self.interfaces = interfaces
        self.aliases = aliases
        self.bridged_interfaces = bridged_interfaces or set()

    def generate(self) -> list[str]:
        """Generate interface configuration commands.

        Generates commands for:
        - Primary interface IP addresses
        - Interface MTU (if specified)
        - Alias (secondary) IP addresses

        Returns:
            List of VyOS 'set' commands for interface configuration
        """
        commands: list[str] = []

        # Build a map of interface -> parent_mask for aliases
        interface_masks: dict[str, str] = {iface.name: iface.mask for iface in self.interfaces}

        # Configure primary interfaces
        for iface in self.interfaces:
            # Skip IP address configuration for bridged interfaces
            # (the IP will be on the bridge interface instead)
            if iface.name not in self.bridged_interfaces:
                # Primary IP address in CIDR notation
                commands.append(f"set interfaces ethernet {iface.name} address {iface.to_cidr()}")

            # MTU (if specified) - always configure even for bridged interfaces
            if iface.mtu is not None:
                commands.append(f"set interfaces ethernet {iface.name} mtu {iface.mtu}")

        # Configure alias (secondary) IP addresses
        for alias in self.aliases:
            # Get parent interface mask for fallback if alias mask is missing
            parent_mask = interface_masks.get(alias.interface)

            if parent_mask is None:
                # This should have been caught by validation, but be defensive
                continue

            # Add alias IP as additional address on the same interface
            cidr = alias.to_cidr(parent_mask)
            commands.append(f"set interfaces ethernet {alias.interface} address {cidr}")

        return commands
