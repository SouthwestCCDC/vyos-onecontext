"""Validation helpers for functional testing.

This module provides infrastructure and helper functions for validating
VyOS router configuration via SSH commands. These helpers are used by
integration tests to verify that contextualization applied configuration
correctly.

Each helper function:
- Takes an ssh_connection callable (from conftest.py)
- Executes VyOS operational mode commands
- Returns a ValidationResult with pass/fail status and diagnostic info

VyOS Command Output Formats:
- show interfaces: Contains "link/ether", "inet" lines with IP addresses
- show configuration | grep host-name: Returns "host-name 'hostname'"
- show configuration | grep public-keys: Returns public-keys stanzas if configured
- show ip ospf: Shows OSPF instance status including router ID
- show configuration commands | grep ospf: Shows OSPF config commands
- show ip route: Returns routing table with protocol codes and next-hop info
"""

import re
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class ValidationResult:
    """Result from a validation check.

    Attributes:
        passed: Whether the validation check passed
        message: Human-readable description of result (why it passed/failed)
        raw_output: Raw command output from VyOS for debugging
    """

    passed: bool
    message: str
    raw_output: str


def check_interface_ip(
    ssh: Callable[[str], str],
    interface: str,
    expected_ip: str,
) -> ValidationResult:
    """Verify an interface has the expected IP address.

    This function queries the interface state using VyOS operational commands
    and validates that the expected IP address is configured and present.

    VyOS Output Format:
        show interfaces ethernet eth0
        Returns output like:
            eth0@NONE: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...
                link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff
                inet 192.168.122.10/24 brd 192.168.122.255 scope global eth0

    Args:
        ssh: SSH connection callable from ssh_connection fixture
        interface: Interface name (e.g., "eth0", "eth1")
        expected_ip: Expected IP address without CIDR notation (e.g., "192.168.122.10")

    Returns:
        ValidationResult indicating whether IP matches and diagnostic info
    """
    try:
        output = ssh(f"show interfaces ethernet {interface}")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query interface {interface}: {e}",
            raw_output="",
        )

    # Look for "inet <ip>/<cidr>" pattern in output
    # Example: "inet 192.168.122.10/24 brd ..."
    ip_pattern = re.compile(r"inet\s+(\d+\.\d+\.\d+\.\d+)/\d+")
    match = ip_pattern.search(output)

    if not match:
        return ValidationResult(
            passed=False,
            message=f"No IP address found on interface {interface}",
            raw_output=output,
        )

    actual_ip = match.group(1)

    if actual_ip == expected_ip:
        return ValidationResult(
            passed=True,
            message=f"Interface {interface} has expected IP {expected_ip}",
            raw_output=output,
        )
    else:
        return ValidationResult(
            passed=False,
            message=f"IP mismatch on {interface}: expected {expected_ip}, got {actual_ip}",
            raw_output=output,
        )


def check_hostname(
    ssh: Callable[[str], str],
    expected: str,
) -> ValidationResult:
    """Verify system hostname matches expected value.

    This function queries the VyOS configuration for the hostname setting
    and validates it matches the expected value.

    VyOS Output Format:
        show configuration | grep host-name
        Returns output like:
            host-name 'test-simple'

    Args:
        ssh: SSH connection callable from ssh_connection fixture
        expected: Expected hostname string

    Returns:
        ValidationResult indicating whether hostname matches and diagnostic info
    """
    try:
        output = ssh("show configuration | grep host-name")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query hostname: {e}",
            raw_output="",
        )

    # Look for "host-name 'hostname'" or "host-name hostname" pattern
    # VyOS config can use single quotes or no quotes
    hostname_pattern = re.compile(r"host-name\s+['\"]?([a-zA-Z0-9_-]+)['\"]?")
    match = hostname_pattern.search(output)

    if not match:
        return ValidationResult(
            passed=False,
            message="No hostname found in configuration",
            raw_output=output,
        )

    actual_hostname = match.group(1)

    if actual_hostname == expected:
        return ValidationResult(
            passed=True,
            message=f"Hostname matches expected value: {expected}",
            raw_output=output,
        )
    else:
        return ValidationResult(
            passed=False,
            message=f"Hostname mismatch: expected {expected}, got {actual_hostname}",
            raw_output=output,
        )


def check_ssh_key_configured(
    ssh: Callable[[str], str],
) -> ValidationResult:
    """Verify SSH public key is present in VyOS configuration.

    This function checks whether any SSH public keys are configured for
    the vyos user. It does not validate specific key content, only that
    at least one key exists in the configuration.

    VyOS Output Format:
        show configuration | grep 'public-keys'
        Returns output like:
                public-keys test-key-1 {
                    key AAAAB3Nza...
                    type ssh-rsa
                }

    Args:
        ssh: SSH connection callable from ssh_connection fixture

    Returns:
        ValidationResult indicating whether SSH keys are configured
    """
    try:
        output = ssh("show configuration | grep 'public-keys' || echo ''")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query SSH key configuration: {e}",
            raw_output="",
        )

    # Check if output contains "public-keys"
    # Empty output or no match means no keys configured
    if "public-keys" in output:
        # Additional validation: should have key type and key data
        has_key_data = "key" in output and "type" in output

        if has_key_data:
            return ValidationResult(
                passed=True,
                message="SSH public key(s) found in configuration",
                raw_output=output,
            )
        else:
            return ValidationResult(
                passed=False,
                message="SSH public-keys stanza found but missing key data or type",
                raw_output=output,
            )
    else:
        return ValidationResult(
            passed=False,
            message="No SSH public keys configured",
            raw_output=output,
        )


def check_ospf_enabled(
    ssh: Callable[[str], str],
) -> ValidationResult:
    """Verify OSPF process is running.

    This function checks whether OSPF routing protocol is enabled and running
    on the VyOS router by querying the OSPF instance status.

    VyOS Output Format:
        show ip ospf
        Returns output like:
            OSPF Routing Process, Router ID: 192.168.122.70
            Supports only single TOS (TOS0) routes
            This implementation conforms to RFC2328
            RFC1583Compatibility flag is disabled
            ...

        Or if OSPF is not running:
            % OSPF instance not found

    Args:
        ssh: SSH connection callable from ssh_connection fixture

    Returns:
        ValidationResult indicating whether OSPF is enabled
    """
    try:
        output = ssh("show ip ospf || echo ''")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query OSPF status: {e}",
            raw_output="",
        )

    # Check for OSPF process indicator
    # "OSPF Routing Process" indicates OSPF is running
    if "OSPF Routing Process" in output:
        return ValidationResult(
            passed=True,
            message="OSPF routing process is running",
            raw_output=output,
        )
    elif "OSPF instance not found" in output or not output.strip():
        return ValidationResult(
            passed=False,
            message="OSPF routing process is not running",
            raw_output=output,
        )
    else:
        # Unexpected output format
        return ValidationResult(
            passed=False,
            message="Unable to determine OSPF status from output",
            raw_output=output,
        )


def check_ospf_router_id(
    ssh: Callable[[str], str],
    expected_id: str,
) -> ValidationResult:
    """Verify OSPF router ID matches expected value.

    This function queries the OSPF instance for the configured router ID
    and validates it matches the expected value.

    VyOS Output Format:
        show ip ospf
        Returns output like:
            OSPF Routing Process, Router ID: 192.168.122.70
            ...

    Args:
        ssh: SSH connection callable from ssh_connection fixture
        expected_id: Expected router ID (IPv4 address format, e.g., "192.168.122.70")

    Returns:
        ValidationResult indicating whether router ID matches
    """
    try:
        output = ssh("show ip ospf")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query OSPF router ID: {e}",
            raw_output="",
        )

    # Look for "Router ID: <ip>" pattern in output
    # Example: "OSPF Routing Process, Router ID: 192.168.122.70"
    router_id_pattern = re.compile(r"Router ID:\s+(\d+\.\d+\.\d+\.\d+)")
    match = router_id_pattern.search(output)

    if not match:
        # Check if OSPF is even running
        if "OSPF instance not found" in output:
            return ValidationResult(
                passed=False,
                message="OSPF is not running (no router ID configured)",
                raw_output=output,
            )
        return ValidationResult(
            passed=False,
            message="No OSPF router ID found in output",
            raw_output=output,
        )

    actual_id = match.group(1)

    if actual_id == expected_id:
        return ValidationResult(
            passed=True,
            message=f"OSPF router ID matches expected value: {expected_id}",
            raw_output=output,
        )
    else:
        return ValidationResult(
            passed=False,
            message=f"OSPF router ID mismatch: expected {expected_id}, got {actual_id}",
            raw_output=output,
        )


def check_ospf_interface(
    ssh: Callable[[str], str],
    interface: str,
    area: str | None = None,
) -> ValidationResult:
    """Verify interface OSPF configuration.

    This function checks whether a specific interface is configured for OSPF
    and optionally validates the OSPF area assignment.

    VyOS Output Format:
        show configuration commands | grep ospf
        Returns output like:
            set protocols ospf interface eth0 area '0.0.0.0'
            set protocols ospf interface eth0 passive
            set protocols ospf parameters router-id '192.168.122.70'

    Args:
        ssh: SSH connection callable from ssh_connection fixture
        interface: Interface name (e.g., "eth0", "eth1")
        area: Expected OSPF area (e.g., "0.0.0.0", "1.2.3.4"). If None, only
              checks if interface is configured in OSPF, regardless of area.

    Returns:
        ValidationResult indicating whether interface OSPF config is correct
    """
    try:
        output = ssh("show configuration commands | grep ospf || echo ''")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query OSPF configuration: {e}",
            raw_output="",
        )

    # Look for interface OSPF configuration
    # Example: "set protocols ospf interface eth0 area '0.0.0.0'"
    # Area can be quoted or unquoted
    interface_pattern = re.compile(
        rf"set protocols ospf interface {re.escape(interface)} area ['\"]?([0-9.]+)['\"]?"
    )
    match = interface_pattern.search(output)

    if not match:
        return ValidationResult(
            passed=False,
            message=f"Interface {interface} is not configured in OSPF",
            raw_output=output,
        )

    actual_area = match.group(1)

    # If area is not specified, just check that interface is in OSPF
    if area is None:
        return ValidationResult(
            passed=True,
            message=f"Interface {interface} is configured in OSPF (area {actual_area})",
            raw_output=output,
        )

    # Validate area matches
    if actual_area == area:
        return ValidationResult(
            passed=True,
            message=f"Interface {interface} is in OSPF area {area}",
            raw_output=output,
        )
    else:
        return ValidationResult(
            passed=False,
            message=f"Interface {interface} area mismatch: expected {area}, got {actual_area}",
            raw_output=output,
        )


def check_route_exists(
    ssh: Callable[[str], str],
    destination: str,
    via: str | None = None,
    interface: str | None = None,
) -> ValidationResult:
    """Verify a route exists in the routing table.

    This function checks if a specific route exists in the VyOS routing table,
    optionally validating the next-hop gateway or outgoing interface.

    VyOS supports two types of static routes:
    1. Gateway routes: Route via next-hop IP address
    2. Interface routes: Route directly connected via interface

    VyOS Output Format:
        show ip route <destination>
        Returns output like:
            S>* 10.0.0.0/8 [1/0] via 192.168.122.1, eth0, weight 1, 00:01:00
            S>* 172.16.0.0/12 [1/0] is directly connected, eth0, weight 1, 00:01:00

        Output format breakdown:
        - S>*: Protocol code (S=static, >=selected, *=FIB)
        - 10.0.0.0/8: Destination network
        - [1/0]: Admin distance/metric
        - via 192.168.122.1: Next-hop gateway (for gateway routes)
        - is directly connected: Interface route indicator
        - eth0: Outgoing interface
        - weight 1, 00:01:00: Additional route info

    Args:
        ssh: SSH connection callable from ssh_connection fixture
        destination: Destination network in CIDR notation (e.g., "10.0.0.0/8")
        via: Expected next-hop gateway IP (optional, for gateway routes)
        interface: Expected outgoing interface (optional)

    Returns:
        ValidationResult indicating whether route exists and matches criteria

    Note:
        At least one of 'via' or 'interface' should be provided for meaningful
        validation. If both are None, only checks if destination exists.
    """
    try:
        output = ssh(f"show ip route {destination}")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query route for {destination}: {e}",
            raw_output="",
        )

    # Check if route exists (should contain the destination)
    if destination not in output:
        return ValidationResult(
            passed=False,
            message=f"Route for {destination} not found in routing table",
            raw_output=output,
        )

    # Parse the route entry
    # Pattern matches both gateway and interface routes
    # Example gateway: "S>* 10.0.0.0/8 [1/0] via 192.168.122.1, eth0"
    # Example interface: "S>* 172.16.0.0/12 [1/0] is directly connected, eth0"

    route_pattern = re.compile(
        r"(?:via\s+([\d.]+)|is\s+directly\s+connected),\s+([\w.-]+)"
    )
    match = route_pattern.search(output)

    if not match:
        return ValidationResult(
            passed=False,
            message=f"Route for {destination} found but could not parse next-hop/interface",
            raw_output=output,
        )

    actual_via = match.group(1)  # May be None for interface routes
    actual_interface = match.group(2)

    # Validate expectations
    failures = []

    if via is not None and actual_via != via:
        if actual_via is None:
            failures.append(
                f"expected gateway route via {via}, "
                "but found interface route (directly connected)"
            )
        else:
            failures.append(f"gateway mismatch (expected {via}, got {actual_via})")

    if interface is not None and actual_interface != interface:
        failures.append(
            f"interface mismatch (expected {interface}, got {actual_interface})"
        )

    if failures:
        return ValidationResult(
            passed=False,
            message=f"Route for {destination} exists but {', '.join(failures)}",
            raw_output=output,
        )

    # Build success message based on what was validated
    details = []
    if via is not None:
        details.append(f"via {via}")
    if interface is not None:
        details.append(f"interface {interface}")

    detail_str = " ".join(details) if details else "exists"

    return ValidationResult(
        passed=True,
        message=f"Route for {destination} {detail_str}",
        raw_output=output,
    )


def check_default_route(
    ssh: Callable[[str], str],
    gateway: str | None = None,
) -> ValidationResult:
    """Verify default route (0.0.0.0/0) exists in routing table.

    This function checks if a default route is configured, optionally
    validating the gateway IP address.

    VyOS Output Format:
        show ip route 0.0.0.0/0
        Returns output like:
            S>* 0.0.0.0/0 [1/0] via 192.168.122.1, eth0, weight 1, 00:01:00

    Args:
        ssh: SSH connection callable from ssh_connection fixture
        gateway: Expected gateway IP for default route (optional)

    Returns:
        ValidationResult indicating whether default route exists and matches
    """
    try:
        output = ssh("show ip route 0.0.0.0/0")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query default route: {e}",
            raw_output="",
        )

    # Check if default route exists
    if "0.0.0.0/0" not in output:
        return ValidationResult(
            passed=False,
            message="Default route (0.0.0.0/0) not found in routing table",
            raw_output=output,
        )

    # If gateway specified, validate it
    if gateway is not None:
        # Look for "via <gateway>" in output
        via_pattern = re.compile(r"via\s+([\d.]+)")
        match = via_pattern.search(output)

        if not match:
            return ValidationResult(
                passed=False,
                message="Default route found but could not parse gateway",
                raw_output=output,
            )

        actual_gateway = match.group(1)

        if actual_gateway != gateway:
            return ValidationResult(
                passed=False,
                message=f"Default route gateway mismatch: expected {gateway}, got {actual_gateway}",
                raw_output=output,
            )

        return ValidationResult(
            passed=True,
            message=f"Default route exists via {gateway}",
            raw_output=output,
        )
    else:
        return ValidationResult(
            passed=True,
            message="Default route exists",
            raw_output=output,
        )
