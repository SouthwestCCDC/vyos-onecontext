"""Service configuration generators for VRF-aware services."""

import logging

from vyos_onecontext.generators.base import BaseGenerator
from vyos_onecontext.generators.vrf import VRF_NAME
from vyos_onecontext.models import InterfaceConfig

logger = logging.getLogger(__name__)


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


class SnmpGenerator(BaseGenerator):
    """Generate SNMP service configuration.

    Configures SNMP with a read-only community string, bound to the first
    management interface IP address.
    """

    def __init__(self, snmp_community: str | None, interfaces: list[InterfaceConfig]):
        """Initialize SNMP generator.

        Args:
            snmp_community: SNMP community string, or None to skip SNMP configuration
            interfaces: List of interface configurations (used to find management IP)
        """
        self.snmp_community = snmp_community
        self.interfaces = interfaces

    def generate(self) -> list[str]:
        """Generate SNMP service commands.

        Emits two VyOS commands: one to configure a read-only community and one
        to bind SNMP to the first management interface IP. If no management
        interface is found, logs a warning and returns an empty list.

        Returns:
            List of VyOS 'set' commands for SNMP service configuration
        """
        if self.snmp_community is None:
            return []

        # Find the first management interface IP
        mgmt_iface = next(
            (iface for iface in self.interfaces if iface.management),
            None,
        )

        if mgmt_iface is None:
            logger.warning(
                "SNMP_COMMUNITY is set but no management interface found; "
                "skipping SNMP listen-address configuration"
            )
            return []

        mgmt_ip = str(mgmt_iface.ip)

        return [
            f"set service snmp community {self.snmp_community} authorization ro",
            f"set service snmp listen-address {mgmt_ip}",
        ]
