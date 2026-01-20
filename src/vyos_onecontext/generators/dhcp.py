"""DHCP server configuration generator."""

from vyos_onecontext.generators.base import BaseGenerator
from vyos_onecontext.models import DhcpConfig


class DhcpGenerator(BaseGenerator):
    """Generate VyOS DHCP server configuration commands.

    Handles DHCP server configuration:
    - DHCP pools with address ranges
    - Shared-network auto-naming (dhcp-{interface})
    - Subnet configuration with options (gateway, DNS, lease time, domain)
    - Static reservations within subnets
    - Authoritative flag (defaults to false per VyOS defaults)

    Design decisions:
    - Shared-network name derived from interface: dhcp-eth1
    - Subnet ID auto-generated (pool index + 1) for uniqueness
    - Multiple ranges per subnet not implemented in v1 (ONE schema limitation)
    - Each pool gets its own shared-network for clarity
    """

    def __init__(self, dhcp: DhcpConfig | None):
        """Initialize DHCP generator.

        Args:
            dhcp: DHCP configuration (None if DHCP is not configured)
        """
        self.dhcp = dhcp

    def generate(self) -> list[str]:
        """Generate DHCP server configuration commands.

        Generates commands for:
        - Shared-network definitions (one per pool)
        - Subnet configuration with CIDR and subnet-id
        - Address ranges (range 0 by default)
        - DHCP options (default-router, name-server, domain-name, lease)
        - Static-mapping for reservations

        Returns:
            List of VyOS 'set' commands for DHCP configuration
        """
        commands: list[str] = []

        # If DHCP is not configured, return empty list
        if self.dhcp is None:
            return commands

        # Generate pool configurations
        for idx, pool in enumerate(self.dhcp.pools):
            shared_network = f"dhcp-{pool.interface}"
            subnet_id = idx + 1  # Subnet IDs start at 1

            # Subnet must be specified in the pool for VyOS Sagitta
            if pool.subnet is None:
                raise ValueError(
                    f"DHCP pool for {pool.interface} missing required 'subnet' field. "
                    "VyOS Sagitta requires explicit subnet specification."
                )

            # Shared-network and subnet definition
            commands.append(
                f"set service dhcp-server shared-network-name {shared_network} "
                f"subnet {pool.subnet} subnet-id {subnet_id}"
            )

            # Range configuration (range 0 is the default/first range)
            commands.append(
                f"set service dhcp-server shared-network-name {shared_network} "
                f"subnet {pool.subnet} range 0 start {pool.range_start}"
            )
            commands.append(
                f"set service dhcp-server shared-network-name {shared_network} "
                f"subnet {pool.subnet} range 0 stop {pool.range_end}"
            )

            # Default gateway option
            commands.append(
                f"set service dhcp-server shared-network-name {shared_network} "
                f"subnet {pool.subnet} option default-router {pool.gateway}"
            )

            # DNS servers option (multiple name-server commands)
            for dns in pool.dns:
                commands.append(
                    f"set service dhcp-server shared-network-name {shared_network} "
                    f"subnet {pool.subnet} option name-server {dns}"
                )

            # Optional: Lease time
            if pool.lease_time is not None:
                commands.append(
                    f"set service dhcp-server shared-network-name {shared_network} "
                    f"subnet {pool.subnet} lease {pool.lease_time}"
                )

            # Optional: Domain name
            if pool.domain is not None:
                commands.append(
                    f"set service dhcp-server shared-network-name {shared_network} "
                    f"subnet {pool.subnet} option domain-name {pool.domain}"
                )

        # Generate static reservations
        # Group reservations by interface to match them with the corresponding shared-network
        for reservation in self.dhcp.reservations:
            shared_network = f"dhcp-{reservation.interface}"

            # Find the subnet for this interface (first pool matching the interface)
            matching_pool = next(
                (pool for pool in self.dhcp.pools if pool.interface == reservation.interface),
                None,
            )

            if matching_pool is None:
                raise ValueError(
                    f"DHCP reservation for interface {reservation.interface} "
                    f"has no corresponding pool definition"
                )

            subnet = matching_pool.subnet
            if subnet is None:
                raise ValueError(
                    f"DHCP pool for {reservation.interface} missing subnet "
                    "(required for reservations)"
                )

            # Static-mapping uses hostname as the mapping name
            mapping_name = reservation.hostname or f"host-{reservation.mac.replace(':', '-')}"

            commands.append(
                f"set service dhcp-server shared-network-name {shared_network} "
                f"subnet {subnet} static-mapping {mapping_name} mac {reservation.mac}"
            )
            commands.append(
                f"set service dhcp-server shared-network-name {shared_network} "
                f"subnet {subnet} static-mapping {mapping_name} ip-address {reservation.ip}"
            )

        return commands
