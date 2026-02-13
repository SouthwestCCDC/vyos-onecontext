"""Relay configuration generator for VRF-based scoring relay.

This module generates VyOS configuration commands for VRF-based relay routing,
which enables a single router to handle multiple isolated network pivots using
Virtual Routing and Forwarding (VRF) tables.

Key components:
- VRF creation and interface binding (one VRF per egress interface)
- Policy-Based Routing (PBR) to route relay traffic to correct VRF
- Destination NAT (DNAT) for subnet-to-subnet translation
- Source NAT (SNAT) with masquerade on egress interfaces
- Proxy-ARP on ingress interface
- VRF-scoped static routes to target networks
"""

from vyos_onecontext.generators.base import BaseGenerator
from vyos_onecontext.models.relay import RelayConfig


class RelayGenerator(BaseGenerator):
    """Generate VyOS commands for VRF-based relay configuration.

    This generator produces all configuration needed for VRF-based relay routing:
    - VRF creation with unique table IDs
    - Interface-to-VRF binding for egress interfaces
    - Policy-based routing to direct relay traffic to correct VRF
    - Subnet-to-subnet NAT (DNAT/SNAT) for relay-to-target translation
    - Proxy-ARP on ingress interface
    - Static routes in VRF context for target networks

    Rule numbering:
    - VRF table IDs: 200, 201, 202... (sequential per pivot)
    - PBR rules: 10, 20, 30... (sequential per target)
    - DNAT rules: 5000, 5010, 5020... (sequential per target)
    - SNAT rules: 5000, 5010, 5020... (sequential per pivot)

    Design decisions:
    - VRF table IDs start at 200 to avoid conflict with management VRF (table 100)
    - NAT rules start at 5000 to avoid conflict with standard NAT (100+ range)
    - PBR rules use increment of 10 to allow manual rule insertion if needed
    - SNAT is per-pivot (not per-target) since all targets in a pivot share egress
    """

    BASE_TABLE_ID = 200  # Start VRF table IDs at 200 (management VRF uses 100)
    DNAT_RULE_START = 5000  # Avoid conflict with standard NAT (idx*100 scheme)
    SNAT_RULE_START = 5000
    PBR_RULE_START = 10
    PBR_RULE_INCREMENT = 10
    NAT_RULE_INCREMENT = 10

    def __init__(self, relay: RelayConfig | None) -> None:
        """Initialize relay generator.

        Args:
            relay: Relay configuration (None if relay is not configured)
        """
        self.relay = relay

    def generate(self) -> list[str]:
        """Generate all relay configuration commands.

        Commands are generated in the correct order for VyOS commit:
        1. VRF creation and interface binding
        2. Policy-based routing (PBR)
        3. Destination NAT (DNAT)
        4. Source NAT (SNAT)
        5. Proxy-ARP
        6. Static routes in VRF context

        Returns:
            List of VyOS 'set' commands for relay configuration
        """
        commands: list[str] = []

        # If relay is not configured, return empty list
        if self.relay is None:
            return commands

        commands.extend(self._generate_vrfs())
        commands.extend(self._generate_pbr())
        commands.extend(self._generate_dnat())
        commands.extend(self._generate_snat())
        commands.extend(self._generate_proxy_arp())
        commands.extend(self._generate_static_routes())

        return commands

    def _generate_vrfs(self) -> list[str]:
        """Create VRFs and bind interfaces.

        Creates one VRF per pivot (egress interface) with sequential table IDs
        starting at 200. Binds each egress interface to its corresponding VRF.

        Returns:
            List of VyOS 'set' commands for VRF configuration
        """
        commands: list[str] = []

        # Type narrowing: we know self.relay is not None because generate() checks
        if self.relay is None:
            return commands

        for idx, pivot in enumerate(self.relay.pivots):
            vrf_name = f"relay_{pivot.egress_interface}"
            table_id = self.BASE_TABLE_ID + idx

            # Create VRF with table ID
            commands.append(f"set vrf name {vrf_name} table {table_id}")

            # Bind egress interface to VRF
            commands.append(f"set interfaces ethernet {pivot.egress_interface} vrf {vrf_name}")

        return commands

    def _generate_pbr(self) -> list[str]:
        """Generate policy-based routing rules.

        Creates PBR rules to route relay traffic to the correct VRF based on
        destination address. One rule per target, applied to ingress interface.

        Returns:
            List of VyOS 'set' commands for PBR configuration
        """
        commands: list[str] = []

        # Type narrowing: we know self.relay is not None because generate() checks
        if self.relay is None:
            return commands

        rule_num = self.PBR_RULE_START

        # Build VRF table ID mapping
        vrf_table_map = {
            pivot.egress_interface: self.BASE_TABLE_ID + idx
            for idx, pivot in enumerate(self.relay.pivots)
        }

        # Create PBR rules for each target
        for pivot in self.relay.pivots:
            table_id = vrf_table_map[pivot.egress_interface]
            for target in pivot.targets:
                commands.append(
                    f"set policy route relay-pbr rule {rule_num} "
                    f"destination address {target.relay_prefix}"
                )
                commands.append(
                    f"set policy route relay-pbr rule {rule_num} set table {table_id}"
                )
                rule_num += self.PBR_RULE_INCREMENT

        # Apply policy to ingress interface
        commands.append(
            f"set interfaces ethernet {self.relay.ingress_interface} "
            f"policy route relay-pbr"
        )

        return commands

    def _generate_dnat(self) -> list[str]:
        """Generate destination NAT (subnet-to-subnet).

        Creates DNAT rules to translate relay addresses to target addresses.
        Uses subnet-to-subnet NAT (netmap) with matching prefix lengths.

        Returns:
            List of VyOS 'set' commands for DNAT configuration
        """
        commands: list[str] = []

        # Type narrowing: we know self.relay is not None because generate() checks
        if self.relay is None:
            return commands

        rule_num = self.DNAT_RULE_START

        for pivot in self.relay.pivots:
            for target in pivot.targets:
                commands.append(
                    f"set nat destination rule {rule_num} "
                    f"inbound-interface name {self.relay.ingress_interface}"
                )
                commands.append(
                    f"set nat destination rule {rule_num} "
                    f"destination address {target.relay_prefix}"
                )
                commands.append(
                    f"set nat destination rule {rule_num} "
                    f"translation address {target.target_prefix}"
                )
                rule_num += self.NAT_RULE_INCREMENT

        return commands

    def _generate_snat(self) -> list[str]:
        """Generate source NAT (masquerade per egress).

        Creates SNAT rules with masquerade on each egress interface.
        One rule per pivot (not per target) since all targets in a pivot
        share the same egress interface.

        Returns:
            List of VyOS 'set' commands for SNAT configuration
        """
        commands: list[str] = []

        # Type narrowing: we know self.relay is not None because generate() checks
        if self.relay is None:
            return commands

        rule_num = self.SNAT_RULE_START

        for pivot in self.relay.pivots:
            commands.append(
                f"set nat source rule {rule_num} "
                f"outbound-interface name {pivot.egress_interface}"
            )
            commands.append(
                f"set nat source rule {rule_num} translation address masquerade"
            )
            rule_num += self.NAT_RULE_INCREMENT

        return commands

    def _generate_proxy_arp(self) -> list[str]:
        """Enable proxy-ARP on ingress interface.

        Enables proxy-ARP so the router responds to ARP requests for relay
        address ranges, even though those addresses are not directly configured
        on the interface.

        Returns:
            List of VyOS 'set' commands for proxy-ARP configuration
        """
        commands: list[str] = []

        # Type narrowing: we know self.relay is not None because generate() checks
        if self.relay is None:
            return commands

        commands.append(
            f"set interfaces ethernet {self.relay.ingress_interface} "
            f"ip enable-proxy-arp"
        )

        return commands

    def _generate_static_routes(self) -> list[str]:
        """Generate static routes in VRF context.

        Creates static routes for target networks in the appropriate VRF.
        Each target gets its own route in the VRF corresponding to its pivot.

        Returns:
            List of VyOS 'set' commands for VRF-scoped static routes
        """
        commands: list[str] = []

        # Type narrowing: we know self.relay is not None because generate() checks
        if self.relay is None:
            return commands

        for pivot in self.relay.pivots:
            vrf_name = f"relay_{pivot.egress_interface}"
            for target in pivot.targets:
                commands.append(
                    f"set vrf name {vrf_name} protocols static route "
                    f"{target.target_prefix} next-hop {target.gateway}"
                )

        return commands
