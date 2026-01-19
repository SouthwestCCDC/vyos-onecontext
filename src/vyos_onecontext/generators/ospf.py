"""OSPF dynamic routing configuration generator."""

from vyos_onecontext.generators.base import BaseGenerator
from vyos_onecontext.models import OspfConfig


class OspfGenerator(BaseGenerator):
    """Generate VyOS OSPF configuration commands.

    Handles OSPF configuration using Sagitta's interface-based approach:
    - Router ID configuration
    - Interface-based area assignment (not network-based)
    - Passive interfaces
    - Cost overrides
    - Route redistribution (connected, static, kernel)
    - Default-information originate

    Design decisions:
    - OSPF scope: Data-plane only, never in management VRF
    - OSPF authentication: None (matches equuleus behavior)
    - OSPF area: Require explicit area assignment per interface
    - Sagitta uses `interface X area Y` syntax (not equuleus `area X network Y`)
    """

    def __init__(self, ospf: OspfConfig | None):
        """Initialize OSPF generator.

        Args:
            ospf: OSPF configuration (None if OSPF is not enabled)
        """
        self.ospf = ospf

    def generate(self) -> list[str]:
        """Generate OSPF configuration commands.

        Generates commands for:
        - Router ID (if specified)
        - Interface area assignments
        - Passive interfaces
        - Cost overrides
        - Route redistribution
        - Default-information originate

        Returns:
            List of VyOS 'set' commands for OSPF configuration
        """
        commands: list[str] = []

        # If OSPF is disabled or not configured, return empty list
        if self.ospf is None or not self.ospf.enabled:
            return commands

        # Router ID (optional - VyOS auto-derives if not set)
        if self.ospf.router_id:
            commands.append(f"set protocols ospf parameters router-id '{self.ospf.router_id}'")

        # Interface configurations (interface-based, Sagitta best practice)
        for iface in self.ospf.interfaces:
            # Area assignment (required for each interface)
            commands.append(f"set protocols ospf interface {iface.name} area '{iface.area}'")

            # Passive interface (advertise network but don't form adjacencies)
            if iface.passive:
                commands.append(f"set protocols ospf interface {iface.name} passive")

            # Cost override (if specified)
            if iface.cost is not None:
                commands.append(f"set protocols ospf interface {iface.name} cost '{iface.cost}'")

        # Route redistribution
        for protocol in self.ospf.redistribute:
            commands.append(f"set protocols ospf redistribute {protocol}")

        # Default-information originate
        if self.ospf.default_information and self.ospf.default_information.originate:
            if self.ospf.default_information.always:
                commands.append("set protocols ospf default-information originate always")
            else:
                commands.append("set protocols ospf default-information originate")

            # Metric for default route (optional)
            if self.ospf.default_information.metric is not None:
                commands.append(
                    f"set protocols ospf default-information originate metric "
                    f"'{self.ospf.default_information.metric}'"
                )

        return commands
