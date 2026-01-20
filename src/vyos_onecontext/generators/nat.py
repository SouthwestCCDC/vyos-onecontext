"""NAT configuration generator.

This module generates VyOS NAT configuration commands for source NAT (masquerading),
destination NAT (port forwarding), and bidirectional 1:1 NAT.
"""

from vyos_onecontext.generators.base import BaseGenerator
from vyos_onecontext.models import NatConfig


class NatGenerator(BaseGenerator):
    """Generate VyOS NAT configuration commands.

    Handles three types of NAT:
    1. Source NAT (SNAT/masquerade) for outbound traffic
    2. Destination NAT (DNAT/port forwarding) for inbound traffic
    3. Bidirectional 1:1 NAT (creates both SNAT and DNAT rules)

    Rule numbering:
    - Source NAT rules: 100, 200, 300...
    - Destination NAT rules: 100, 200, 300...
    - Binat source rules: 500, 600, 700...
    - Binat destination rules: 500, 600, 700...

    Design decisions:
    - Source and destination NAT use separate numbering spaces
    - Binat rules use higher numbers (500+) to avoid conflicts
    - Rule increment is 100 to allow manual rule insertion if needed
    """

    def __init__(self, nat: NatConfig | None):
        """Initialize NAT generator.

        Args:
            nat: NAT configuration (None if NAT is not configured)
        """
        self.nat = nat

    def generate(self) -> list[str]:
        """Generate all NAT configuration commands.

        Returns:
            List of VyOS 'set' commands for NAT configuration
        """
        commands: list[str] = []

        # If NAT is not configured, return empty list
        if self.nat is None:
            return commands

        # Generate source NAT rules
        commands.extend(self._generate_source_nat())

        # Generate destination NAT rules
        commands.extend(self._generate_destination_nat())

        # Generate bidirectional 1:1 NAT rules
        commands.extend(self._generate_binat())

        return commands

    def _generate_source_nat(self) -> list[str]:
        """Generate source NAT (SNAT) rules.

        Source NAT is used for outbound traffic, typically masquerading internal
        addresses to a public IP. Supports both dynamic masquerade and static SNAT.

        Rule numbering starts at 100, increments by 100.

        Returns:
            List of VyOS 'set' commands for source NAT rules
        """
        commands: list[str] = []

        # Type narrowing: we know self.nat is not None because generate() checks
        if self.nat is None:
            return commands

        for idx, rule in enumerate(self.nat.source, start=1):
            rule_num = idx * 100

            # Outbound interface (required)
            commands.append(
                f"set nat source rule {rule_num} "
                f"outbound-interface name '{rule.outbound_interface}'"
            )

            # Source address (optional - if not specified, matches all sources)
            if rule.source_address:
                commands.append(
                    f"set nat source rule {rule_num} source address '{rule.source_address}'"
                )

            # Translation (masquerade or static address)
            if rule.translation == "masquerade":
                commands.append(f"set nat source rule {rule_num} translation address 'masquerade'")
            elif rule.translation_address:
                commands.append(
                    f"set nat source rule {rule_num} "
                    f"translation address '{rule.translation_address}'"
                )

            # Description (optional)
            if rule.description:
                commands.append(f"set nat source rule {rule_num} description '{rule.description}'")

        return commands

    def _generate_destination_nat(self) -> list[str]:
        """Generate destination NAT (DNAT) rules.

        Destination NAT is used for inbound traffic, typically port forwarding
        from public IPs to internal services.

        Rule numbering starts at 100, increments by 100.

        Returns:
            List of VyOS 'set' commands for destination NAT rules
        """
        commands: list[str] = []

        # Type narrowing: we know self.nat is not None because generate() checks
        if self.nat is None:
            return commands

        for idx, rule in enumerate(self.nat.destination, start=1):
            rule_num = idx * 100

            # Inbound interface (required)
            commands.append(
                f"set nat destination rule {rule_num} "
                f"inbound-interface name '{rule.inbound_interface}'"
            )

            # Protocol (optional - if not specified, matches all protocols)
            if rule.protocol:
                # Handle tcp_udp specially - need to set both protocols
                if rule.protocol == "tcp_udp":
                    commands.append(f"set nat destination rule {rule_num} protocol 'tcp_udp'")
                else:
                    commands.append(
                        f"set nat destination rule {rule_num} protocol '{rule.protocol}'"
                    )

            # Destination address (optional - for 1:1 NAT scenarios)
            if rule.destination_address:
                commands.append(
                    f"set nat destination rule {rule_num} "
                    f"destination address '{rule.destination_address}'"
                )

            # Destination port (optional - not used with ICMP)
            if rule.destination_port is not None:
                commands.append(
                    f"set nat destination rule {rule_num} "
                    f"destination port '{rule.destination_port}'"
                )

            # Translation address (required)
            commands.append(
                f"set nat destination rule {rule_num} "
                f"translation address '{rule.translation_address}'"
            )

            # Translation port (optional - if not specified, port is preserved)
            if rule.translation_port is not None:
                commands.append(
                    f"set nat destination rule {rule_num} "
                    f"translation port '{rule.translation_port}'"
                )

            # Description (optional)
            if rule.description:
                commands.append(
                    f"set nat destination rule {rule_num} description '{rule.description}'"
                )

        return commands

    def _generate_binat(self) -> list[str]:
        """Generate bidirectional 1:1 NAT rules.

        Bidirectional NAT creates paired source and destination NAT rules to provide
        full bidirectional translation between an external (public) IP and an internal IP.

        Typical use case: Exposing an internal server with a dedicated public IP where
        both inbound and outbound traffic should use that public IP.

        Rule numbering starts at 500 for both source and destination rules to avoid
        conflicts with standalone NAT rules.

        Returns:
            List of VyOS 'set' commands for bidirectional NAT rules
        """
        commands: list[str] = []

        # Type narrowing: we know self.nat is not None because generate() checks
        if self.nat is None:
            return commands

        for idx, rule in enumerate(self.nat.binat, start=1):
            # Start binat rules at 500 to avoid conflicts with regular NAT rules
            rule_num = 500 + (idx - 1) * 100

            # Destination NAT rule (inbound: external -> internal)
            commands.append(
                f"set nat destination rule {rule_num} inbound-interface name '{rule.interface}'"
            )
            commands.append(
                f"set nat destination rule {rule_num} destination address '{rule.external_address}'"
            )
            commands.append(
                f"set nat destination rule {rule_num} translation address '{rule.internal_address}'"
            )

            # Source NAT rule (outbound: internal -> external)
            commands.append(
                f"set nat source rule {rule_num} outbound-interface name '{rule.interface}'"
            )
            commands.append(
                f"set nat source rule {rule_num} source address '{rule.internal_address}'"
            )
            commands.append(
                f"set nat source rule {rule_num} translation address '{rule.external_address}'"
            )

            # Description (applied to both rules if provided)
            if rule.description:
                commands.append(
                    f"set nat destination rule {rule_num} description '{rule.description}'"
                )
                commands.append(f"set nat source rule {rule_num} description '{rule.description}'")

        return commands
