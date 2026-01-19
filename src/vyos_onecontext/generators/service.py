"""Service configuration generators for VRF-aware services."""

from vyos_onecontext.generators.base import BaseGenerator
from vyos_onecontext.generators.vrf import VRF_NAME
from vyos_onecontext.models import InterfaceConfig


class SshServiceGenerator(BaseGenerator):
    """Generate SSH service configuration.

    Configures SSH to listen in management VRF if any management
    interfaces are defined.
    """

    def __init__(self, interfaces: list[InterfaceConfig]):
        """Initialize SSH service generator.

        Args:
            interfaces: List of interface configurations
        """
        self.interfaces = interfaces

    def generate(self) -> list[str]:
        """Generate SSH service commands.

        If any interface has management=True, binds SSH to the management VRF.
        Otherwise, returns empty list (SSH uses default/global).

        Returns:
            List of VyOS 'set' commands for SSH service configuration
        """
        has_management_vrf = any(iface.management for iface in self.interfaces)

        if not has_management_vrf:
            return []

        return [f"set service ssh vrf {VRF_NAME}"]
