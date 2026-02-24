"""Relay configuration generator for VRF-based scoring relay.

This module generates VyOS configuration commands for VRF-based relay routing,
which enables a single router to handle multiple isolated network pivots using
Virtual Routing and Forwarding (VRF) tables.

Key components:
- VRF creation and interface binding (one VRF for ingress, one VRF per egress interface)
- Policy-Based Routing (PBR) to route relay traffic from ingress VRF to correct egress VRF
- Destination NAT (DNAT) for subnet-to-subnet translation
- Source NAT (SNAT) with masquerade on egress interfaces
- Proxy-ARP on ingress interface
- VRF-scoped static routes to target networks
"""

from vyos_onecontext.generators.base import BaseGenerator
from vyos_onecontext.models.interface import InterfaceConfig
from vyos_onecontext.models.relay import RelayConfig


class RelayGenerator(BaseGenerator):
    """Generate VyOS commands for VRF-based relay configuration.

    This generator produces all configuration needed for VRF-based relay routing:
    - VRF creation with unique table IDs (ingress VRF + egress VRFs)
    - Interface-to-VRF binding for ingress and egress interfaces
    - Policy-based routing to direct relay traffic from ingress VRF to correct egress VRF
    - Subnet-to-subnet NAT (DNAT/SNAT) for relay-to-target translation
    - Proxy-ARP on ingress interface
    - Static routes in egress VRF context for target networks

    Rule numbering:
    - Ingress VRF table ID: 149
    - Egress VRF table IDs: 150, 151, 152... (sequential per pivot)
    - PBR rules: 10, 20, 30... (sequential per target)
    - DNAT rules: 5000, 5010, 5020... (sequential per target)
    - SNAT rules: 5000, 5010, 5020... (sequential per pivot)

    Design decisions:
    - Ingress VRF table ID is 149 (just before egress VRFs)
    - Egress VRF table IDs start at 150 (management VRF uses 100, VyOS max is 200)
    - NAT rules start at 5000 to avoid conflict with standard NAT (100+ range)
    - PBR rules use increment of 10 to allow manual rule insertion if needed
    - SNAT is per-pivot (not per-target) since all targets in a pivot share egress
    - PBR routes traffic cross-VRF from ingress VRF to egress VRFs
    """

    INGRESS_VRF_TABLE_ID = 149  # Table ID for ingress VRF (one less than BASE_TABLE_ID)
    BASE_TABLE_ID = 150  # Start VRF table IDs at 150 (management VRF uses 100, VyOS max is 200)
    DNAT_RULE_START = 5000  # Avoid conflict with standard NAT (idx*100 scheme)
    SNAT_RULE_START = 5000
    PBR_RULE_START = 10
    PBR_RULE_INCREMENT = 10
    NAT_RULE_INCREMENT = 10

    def __init__(
        self, relay: RelayConfig | None, interfaces: list[InterfaceConfig] | None = None
    ) -> None:
        """Initialize relay generator.

        Args:
            relay: Relay configuration (None if relay is not configured)
            interfaces: List of interface configurations (needed for ingress gateway)
        """
        self.relay = relay
        self.interfaces = interfaces or []

    def generate(self) -> list[str]:
        """Generate all relay configuration commands.

        Commands are generated in the correct order for VyOS commit:
        1. VRF creation and interface binding
        2. Ingress VRF default route
        3. Cross-VRF proxy-ARP routes
        4. Policy-based routing (PBR)
        5. Destination NAT (DNAT)
        6. Source NAT (SNAT)
        7. Proxy-ARP
        8. Static routes in egress VRF context
        9. Egress VRF default routes (return path)

        Returns:
            List of VyOS 'set' commands for relay configuration
        """
        commands: list[str] = []

        # If relay is not configured, return empty list
        if self.relay is None:
            return commands

        commands.extend(self._generate_vrfs())
        commands.extend(self._generate_ingress_default_route())
        commands.extend(self._generate_proxy_arp_routes())
        commands.extend(self._generate_pbr())
        commands.extend(self._generate_dnat())
        commands.extend(self._generate_snat())
        commands.extend(self._generate_proxy_arp())
        commands.extend(self._generate_static_routes())
        commands.extend(self._generate_egress_default_routes())

        return commands

    def generate_vrf_commands(self) -> list[str]:
        """Generate VRF creation and interface binding commands.

        Must be called BEFORE interface IP configuration.

        Returns:
            List of VyOS 'set' commands for VRF configuration
        """
        if self.relay is None:
            return []
        return self._generate_vrfs()

    def generate_relay_commands(self) -> list[str]:
        """Generate PBR, NAT, proxy-ARP, and static route commands.

        Must be called AFTER interface IP configuration.

        Returns:
            List of VyOS 'set' commands for relay configuration (excluding VRF creation)
        """
        if self.relay is None:
            return []

        commands: list[str] = []
        commands.extend(self._generate_ingress_default_route())
        commands.extend(self._generate_proxy_arp_routes())
        commands.extend(self._generate_pbr())
        commands.extend(self._generate_dnat())
        commands.extend(self._generate_snat())
        commands.extend(self._generate_proxy_arp())
        commands.extend(self._generate_static_routes())
        commands.extend(self._generate_egress_default_routes())

        return commands

    def _generate_vrfs(self) -> list[str]:
        """Create VRFs and bind interfaces.

        Creates one VRF for the ingress interface and one VRF per pivot (egress interface).
        The ingress VRF uses table ID 149, egress VRFs use sequential table IDs starting at 150.

        Returns:
            List of VyOS 'set' commands for VRF configuration
        """
        commands: list[str] = []

        # Type narrowing: we know self.relay is not None because generate() checks
        if self.relay is None:
            return commands

        # Create ingress VRF and bind ingress interface
        ingress_vrf_name = f"relay_{self.relay.ingress_interface}"
        commands.append(f"set vrf name {ingress_vrf_name} table {self.INGRESS_VRF_TABLE_ID}")
        commands.append(
            f"set interfaces ethernet {self.relay.ingress_interface} vrf {ingress_vrf_name}"
        )

        # Create egress VRFs and bind egress interfaces
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
            f"set policy route relay-pbr interface {self.relay.ingress_interface}"
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
        address ranges. The relay addresses are covered by the /12 subnet
        configured on the ingress interface (e.g., 10.40.17.1/12 covers all
        10.40-47.x addresses), so no additional routes are needed for proxy-ARP
        to function correctly.

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

    def _get_ingress_gateway(self) -> str | None:
        """Get the gateway IP for the ingress interface.

        Looks up the ingress interface in the interfaces list and returns
        its configured gateway, if present.

        Returns:
            Gateway IP address as string, or None if not configured
        """
        if self.relay is None:
            return None

        # Find the ingress interface configuration
        for iface in self.interfaces:
            if iface.name == self.relay.ingress_interface:
                if iface.gateway is None:
                    return None
                return str(iface.gateway)

        # Ingress interface not found in interfaces list
        return None

    def _generate_ingress_default_route(self) -> list[str]:
        """Generate default route in ingress VRF.

        Creates a default route in the ingress VRF pointing to the gateway
        configured on the ingress interface. This allows return traffic from
        egress VRFs to reach the scoring engine.

        Returns:
            List of VyOS 'set' commands for ingress VRF default route
        """
        commands: list[str] = []

        # Type narrowing: we know self.relay is not None because generate() checks
        if self.relay is None:
            return commands

        gateway = self._get_ingress_gateway()
        if gateway is None:
            # No gateway configured on ingress interface - skip default route
            return commands

        ingress_vrf_name = f"relay_{self.relay.ingress_interface}"
        commands.append(
            f"set vrf name {ingress_vrf_name} protocols static route 0.0.0.0/0 next-hop {gateway}"
        )

        return commands

    def _generate_proxy_arp_routes(self) -> list[str]:
        """Generate cross-VRF interface routes for proxy-ARP.

        The kernel only performs proxy-ARP when it has a route to the target
        via a DIFFERENT interface than where the ARP request arrived. Since all
        relay addresses fall within the /12 connected subnet on the ingress
        interface, the kernel sees them as "same interface" routes and won't
        proxy-ARP.

        Solution: Add cross-VRF interface routes in the ingress VRF pointing
        to each relay prefix via the egress interface. This gives the kernel
        a route via a different interface, enabling proxy-ARP.

        For each relay target, generates:
            set vrf name relay_{ingress} protocols static route {relay_prefix}
                interface {egress} vrf relay_{egress}

        Returns:
            List of VyOS 'set' commands for cross-VRF proxy-ARP routes
        """
        commands: list[str] = []

        # Type narrowing: we know self.relay is not None because generate() checks
        if self.relay is None:
            return commands

        ingress_vrf_name = f"relay_{self.relay.ingress_interface}"

        for pivot in self.relay.pivots:
            egress_vrf_name = f"relay_{pivot.egress_interface}"
            for target in pivot.targets:
                commands.append(
                    f"set vrf name {ingress_vrf_name} protocols static route "
                    f"{target.relay_prefix} interface {pivot.egress_interface} "
                    f"vrf {egress_vrf_name}"
                )

        return commands

    def _generate_egress_default_routes(self) -> list[str]:
        """Generate cross-VRF default routes in egress VRFs.

        Creates a default route in each egress VRF pointing back to the ingress
        VRF gateway. This enables return traffic routing: when a reply arrives
        on an egress interface and conntrack reverses the NAT, the egress VRF
        needs a route back to the original sender in the ingress VRF.

        For each pivot (egress VRF), generates:
            set vrf name relay_{egress_interface} protocols static route 0.0.0.0/0
                next-hop {ingress_gateway} vrf relay_{ingress_interface}

        Only generates routes if a gateway is configured on the ingress interface.

        Returns:
            List of VyOS 'set' commands for egress VRF default routes
        """
        commands: list[str] = []

        # Type narrowing: we know self.relay is not None because generate() checks
        if self.relay is None:
            return commands

        gateway = self._get_ingress_gateway()
        if gateway is None:
            # No gateway configured on ingress interface - skip default routes
            return commands

        ingress_vrf_name = f"relay_{self.relay.ingress_interface}"

        for pivot in self.relay.pivots:
            egress_vrf_name = f"relay_{pivot.egress_interface}"
            commands.append(
                f"set vrf name {egress_vrf_name} protocols static route 0.0.0.0/0 "
                f"next-hop {gateway} vrf {ingress_vrf_name}"
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
