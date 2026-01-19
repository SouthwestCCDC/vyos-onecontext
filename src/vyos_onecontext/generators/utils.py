"""Shared utility functions for generators."""

import re

from vyos_onecontext.models import InterfaceConfig


def natural_sort_key(iface: InterfaceConfig) -> float:
    """Extract numeric portion of interface name for natural sorting.

    Ensures eth2 sorts before eth10 (numeric order, not lexicographic).
    Non-eth interfaces are sorted after all numbered eth interfaces.

    Args:
        iface: Interface configuration object

    Returns:
        Float representing sort order (interface number or infinity for non-eth)
    """
    match = re.match(r"eth(\d+)", iface.name)
    return float(match.group(1)) if match else float("inf")
