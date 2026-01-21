"""Firewall configuration generator.

This module generates VyOS zone-based firewall configuration commands including:
- Firewall groups (network, address, port groups)
- Firewall zones with interface assignments
- Global state policies (established/related/invalid)
- Inter-zone policies with filtering rules
"""

from vyos_onecontext.generators.base import BaseGenerator
from vyos_onecontext.models import FirewallConfig


class FirewallGenerator(BaseGenerator):
    """Generate VyOS zone-based firewall configuration commands.

    Handles four main aspects of firewall configuration:
    1. Groups - Reusable sets of networks, addresses, or ports
    2. Zones - Security zones with interface membership
    3. Global state policies - Automatic handling of established/related/invalid traffic
    4. Zone policies - Filtering rules between zone pairs

    Rule numbering:
    - Zone policy rules: 100, 200, 300...
    - Increment is 100 to allow manual rule insertion if needed
    """

    def __init__(self, firewall: FirewallConfig | None):
        """Initialize firewall generator.

        Args:
            firewall: Firewall configuration (None if firewall is not configured)
        """
        self.firewall = firewall

    def generate(self) -> list[str]:
        """Generate all firewall configuration commands.

        Returns:
            List of VyOS 'set' commands for firewall configuration
        """
        commands: list[str] = []

        # If firewall is not configured, return empty list
        if self.firewall is None:
            return commands

        # Generate global state policies (must come first)
        commands.extend(self._generate_global_state_policy())

        # Generate firewall groups
        commands.extend(self._generate_groups())

        # Generate firewall zones
        commands.extend(self._generate_zones())

        # Generate inter-zone policies
        commands.extend(self._generate_policies())

        return commands

    def _generate_global_state_policy(self) -> list[str]:
        """Generate global state-based firewall policies.

        These policies automatically handle connection state across all traffic:
        - established: Accept packets from established connections
        - related: Accept packets related to established connections (e.g., FTP data)
        - invalid: Drop malformed or suspicious packets

        This is a security best practice that applies globally before zone rules.

        Returns:
            List of VyOS 'set' commands for global state policies
        """
        commands: list[str] = []

        commands.append("set firewall global-options state-policy established action accept")
        commands.append("set firewall global-options state-policy related action accept")
        commands.append("set firewall global-options state-policy invalid action drop")

        return commands

    def _generate_groups(self) -> list[str]:
        """Generate firewall group definitions.

        Firewall groups allow defining named sets of networks, addresses, or ports
        that can be referenced in firewall rules. This promotes reusability and
        cleaner rule definitions.

        Types:
        - network-group: CIDR network ranges (e.g., 10.0.0.0/8)
        - address-group: Individual IP addresses (e.g., 10.1.1.1)
        - port-group: Port numbers (e.g., 80, 443)

        Returns:
            List of VyOS 'set' commands for firewall groups
        """
        commands: list[str] = []

        # Type narrowing: we know self.firewall is not None because generate() checks
        if self.firewall is None:
            return commands

        # Network groups (CIDR notation)
        for group_name, networks in self.firewall.groups.network.items():
            for network in networks:
                commands.append(
                    f"set firewall group network-group {group_name} network '{network}'"
                )

        # Address groups (individual IPs)
        for group_name, addresses in self.firewall.groups.address.items():
            for address in addresses:
                commands.append(
                    f"set firewall group address-group {group_name} address '{address}'"
                )

        # Port groups
        for group_name, ports in self.firewall.groups.port.items():
            for port in ports:
                commands.append(f"set firewall group port-group {group_name} port {port}")

        return commands

    def _generate_zones(self) -> list[str]:
        """Generate firewall zone definitions.

        Zones group interfaces by security level and define default actions.
        Each zone has:
        - Name (e.g., WAN, GAME, SCORING)
        - Interface membership
        - Default action (drop or reject) when no policy rules match

        Security note: default_action cannot be 'accept' (enforced by model).

        Returns:
            List of VyOS 'set' commands for firewall zones
        """
        commands: list[str] = []

        # Type narrowing: we know self.firewall is not None because generate() checks
        if self.firewall is None:
            return commands

        for zone_name, zone in self.firewall.zones.items():
            # Add interfaces to zone
            for interface in zone.interfaces:
                commands.append(f"set firewall zone {zone_name} interface {interface}")

            # Set default action for zone
            commands.append(f"set firewall zone {zone_name} default-action {zone.default_action}")

        return commands

    def _generate_policies(self) -> list[str]:
        """Generate inter-zone firewall policies.

        Policies define filtering rules for traffic flowing from one zone to another.
        Each policy consists of:
        - Source zone (from)
        - Destination zone (to)
        - Named ruleset (e.g., "GAME-to-SCORING")
        - Ordered list of rules with actions

        Rule numbering starts at 100, increments by 100.

        Returns:
            List of VyOS 'set' commands for inter-zone policies
        """
        commands: list[str] = []

        # Type narrowing: we know self.firewall is not None because generate() checks
        if self.firewall is None:
            return commands

        for policy in self.firewall.policies:
            # Create ruleset name (e.g., "GAME-to-SCORING")
            ruleset_name = f"{policy.from_zone}-to-{policy.to_zone}"

            # Set default action for this ruleset (typically drop)
            # Note: We use 'drop' as the default since zone default_action can only be drop/reject
            commands.append(f"set firewall ipv4 name {ruleset_name} default-action drop")

            # Generate rules for this policy
            for idx, rule in enumerate(policy.rules, start=1):
                rule_num = idx * 100

                # Action (accept, drop, reject)
                commands.append(
                    f"set firewall ipv4 name {ruleset_name} rule {rule_num} action {rule.action}"
                )

                # Protocol (tcp, udp, icmp, tcp_udp)
                if rule.protocol:
                    # Handle tcp_udp specially - VyOS uses 'tcp_udp' syntax
                    commands.append(
                        f"set firewall ipv4 name {ruleset_name} rule {rule_num} "
                        f"protocol {rule.protocol}"
                    )

                # Source filters (address, address-group, or network-group)
                if rule.source_address:
                    commands.append(
                        f"set firewall ipv4 name {ruleset_name} rule {rule_num} "
                        f"source address {rule.source_address}"
                    )
                if rule.source_address_group:
                    commands.append(
                        f"set firewall ipv4 name {ruleset_name} rule {rule_num} "
                        f"source group address-group {rule.source_address_group}"
                    )
                if rule.source_network_group:
                    commands.append(
                        f"set firewall ipv4 name {ruleset_name} rule {rule_num} "
                        f"source group network-group {rule.source_network_group}"
                    )

                # Destination filters (address, address-group, or network-group)
                if rule.destination_address:
                    commands.append(
                        f"set firewall ipv4 name {ruleset_name} rule {rule_num} "
                        f"destination address {rule.destination_address}"
                    )
                if rule.destination_address_group:
                    commands.append(
                        f"set firewall ipv4 name {ruleset_name} rule {rule_num} "
                        f"destination group address-group {rule.destination_address_group}"
                    )
                if rule.destination_network_group:
                    commands.append(
                        f"set firewall ipv4 name {ruleset_name} rule {rule_num} "
                        f"destination group network-group {rule.destination_network_group}"
                    )

                # Destination port filters (inline or port-group)
                if rule.destination_port is not None:
                    # Handle both single port and list of ports
                    if isinstance(rule.destination_port, list):
                        # For multiple ports, generate separate commands for each
                        for port in rule.destination_port:
                            commands.append(
                                f"set firewall ipv4 name {ruleset_name} rule {rule_num} "
                                f"destination port {port}"
                            )
                    else:
                        commands.append(
                            f"set firewall ipv4 name {ruleset_name} rule {rule_num} "
                            f"destination port {rule.destination_port}"
                        )
                if rule.destination_port_group:
                    commands.append(
                        f"set firewall ipv4 name {ruleset_name} rule {rule_num} "
                        f"destination group port-group {rule.destination_port_group}"
                    )

                # ICMP type filter (only valid when protocol is icmp)
                if rule.icmp_type:
                    commands.append(
                        f"set firewall ipv4 name {ruleset_name} rule {rule_num} "
                        f"icmp type-name {rule.icmp_type}"
                    )

                # Description
                if rule.description:
                    commands.append(
                        f"set firewall ipv4 name {ruleset_name} rule {rule_num} "
                        f"description '{rule.description}'"
                    )

            # Bind ruleset to zone pair
            commands.append(
                f"set firewall zone {policy.from_zone} from {policy.to_zone} "
                f"firewall name {ruleset_name}"
            )

        return commands
