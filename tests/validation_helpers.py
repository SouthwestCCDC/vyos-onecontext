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
- show configuration commands | grep 'nat source': Returns NAT source set commands
- show configuration commands | grep 'nat destination': Returns NAT dest set commands
- show vrf: Shows VRF list and details
"""


import ipaddress
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
    # Limit octets to 1-3 digits to prevent matching invalid IPs like 999.999.999.999
    ip_pattern = re.compile(r"inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/\d+")
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
    # Per RFC 952/1123, hostnames cannot contain underscores
    hostname_pattern = re.compile(r"host-name\s+['\"]?([a-zA-Z0-9-]+)['\"]?")
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

        ECMP (Equal-Cost Multi-Path) routes:
            Multiple routes to same destination with different next-hops
            S>* 10.0.0.0/8 [1/0] via 192.168.122.1, eth0, weight 1, 00:01:00
            S>* 10.0.0.0/8 [1/0] via 192.168.122.2, eth1, weight 1, 00:01:00

    Args:
        ssh: SSH connection callable from ssh_connection fixture
        destination: Destination network in CIDR notation (e.g., "10.0.0.0/8")
        via: Expected next-hop gateway IP (optional, for gateway routes)
        interface: Expected outgoing interface (optional)

    Returns:
        ValidationResult indicating whether route exists and matches criteria

    Note:
        - At least one of 'via' or 'interface' should be provided for meaningful
          validation. If both are None, only checks if destination exists.
        - Only supports IPv4 routes. IPv6 routes require 'show ipv6 route'.
        - Queries default routing table. VRF routes require different commands.
    """
    # Validate destination is valid CIDR
    # Require explicit prefix notation (e.g., "10.0.0.0/8" not "10.0.0.1")
    if "/" not in destination:
        return ValidationResult(
            passed=False,
            message=(
                f"Invalid destination CIDR '{destination}': "
                "must include prefix length (e.g., '10.0.0.0/8')"
            ),
            raw_output="",
        )

    try:
        ipaddress.ip_network(destination, strict=False)
    except ValueError as e:
        return ValidationResult(
            passed=False,
            message=f"Invalid destination CIDR '{destination}': {e}",
            raw_output="",
        )

    # Validate via parameter if provided
    if via is not None:
        try:
            addr = ipaddress.ip_address(via)
            # Only IPv4 addresses are supported (show ip route is IPv4-only)
            if not isinstance(addr, ipaddress.IPv4Address):
                return ValidationResult(
                    passed=False,
                    message=(
                        f"Invalid gateway IP '{via}': "
                        "IPv6 addresses not supported (use 'show ipv6 route')"
                    ),
                    raw_output="",
                )
        except ValueError as e:
            return ValidationResult(
                passed=False,
                message=f"Invalid gateway IP '{via}': {e}",
                raw_output="",
            )

    try:
        output = ssh(f"show ip route {destination}")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query route for {destination}: {e}",
            raw_output="",
        )

    # Check for VyOS error messages BEFORE checking if destination in output
    # This prevents false positives where error messages might contain the destination
    error_indicators = [
        "Invalid value",
        "Configuration path",
        "Error:",
    ]
    for indicator in error_indicators:
        if indicator in output:
            return ValidationResult(
                passed=False,
                message=f"VyOS error querying route for {destination}: {output.strip()}",
                raw_output=output,
            )

    # Check if route exists (should contain the destination)
    # "% Network not in table" is VyOS's way of saying route doesn't exist
    # Note: We check "Network not in table" BEFORE checking if destination in output
    # to avoid substring matches in error messages
    if "Network not in table" in output or destination not in output:
        return ValidationResult(
            passed=False,
            message=f"Route for {destination} not found in routing table",
            raw_output=output,
        )

    # Parse the route entry
    # Pattern matches both gateway and interface routes, including VTI and aliases
    # Example gateway: "S>* 10.0.0.0/8 [1/0] via 192.168.122.1, eth0"
    # Example interface: "S>* 172.16.0.0/12 [1/0] is directly connected, eth0"
    # Example VTI: "via 192.168.1.1, vti@NONE"
    # Example alias: "via 192.168.1.1, eth0:1"

    # Updated regex to support:
    # - IPv4 addresses ([\d.]+)
    # - VTI interfaces with @ symbol ([\w.@:-]+)
    # - Interface aliases with colon ([\w.@:-]+)
    route_pattern = re.compile(
        r"(?:via\s+([\d.]+)|is\s+directly\s+connected),\s+([\w.@:-]+)"
    )

    # Use findall to get ALL routes (handles ECMP)
    matches = route_pattern.findall(output)

    if not matches:
        return ValidationResult(
            passed=False,
            message=f"Route for {destination} found but could not parse next-hop/interface",
            raw_output=output,
        )

    # Check if ANY route matches the criteria (for ECMP support)
    for match in matches:
        actual_via = match[0] if match[0] else None  # Empty string becomes None
        actual_interface = match[1]

        # Check if this route matches expectations
        via_matches = via is None or actual_via == via
        interface_matches = interface is None or actual_interface == interface

        if via_matches and interface_matches:
            # Found a matching route
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

    # No matching route found - build failure message
    failures = []

    # Get the first route for error reporting
    first_via = matches[0][0] if matches[0][0] else None

    if via is not None:
        if first_via is None:
            failures.append(
                f"expected gateway route via {via}, "
                "but found interface route (directly connected)"
            )
        else:
            found_gateways = [m[0] for m in matches if m[0]]
            failures.append(
                f"gateway mismatch (expected {via}, found {', '.join(found_gateways)})"
            )

    if interface is not None:
        found_interfaces = [m[1] for m in matches]
        failures.append(
            f"interface mismatch (expected {interface}, found {', '.join(found_interfaces)})"
        )

    return ValidationResult(
        passed=False,
        message=f"Route for {destination} exists but {', '.join(failures)}",
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
    # Validate gateway parameter if provided
    if gateway is not None:
        try:
            addr = ipaddress.ip_address(gateway)
            # Only IPv4 addresses are supported (show ip route is IPv4-only)
            if not isinstance(addr, ipaddress.IPv4Address):
                return ValidationResult(
                    passed=False,
                    message=(
                        f"Invalid gateway IP '{gateway}': "
                        "IPv6 addresses not supported (use 'show ipv6 route')"
                    ),
                    raw_output="",
                )
        except ValueError as e:
            return ValidationResult(
                passed=False,
                message=f"Invalid gateway IP '{gateway}': {e}",
                raw_output="",
            )

    try:
        output = ssh("show ip route 0.0.0.0/0")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query default route: {e}",
            raw_output="",
        )

    # Check for VyOS error messages BEFORE checking if destination in output
    # This prevents false positives where error messages might contain the destination
    error_indicators = ["Invalid value", "Configuration path", "Error:"]
    for indicator in error_indicators:
        if indicator in output:
            return ValidationResult(
                passed=False,
                message=f"VyOS error querying default route: {output.strip()}",
                raw_output=output,
            )

    # Check if default route exists
    # "% Network not in table" is VyOS's way of saying route doesn't exist
    # Note: We check "Network not in table" BEFORE checking if destination in output
    # to avoid substring matches in error messages
    if "Network not in table" in output or "0.0.0.0/0" not in output:
        return ValidationResult(
            passed=False,
            message="Default route (0.0.0.0/0) not found in routing table",
            raw_output=output,
        )

    # If gateway specified, validate it
    if gateway is not None:
        # Look for "via <gateway>" in output
        # Use findall to support ECMP routes with multiple gateways
        via_pattern = re.compile(r"via\s+([\d.]+)")
        matches = via_pattern.findall(output)

        if not matches:
            return ValidationResult(
                passed=False,
                message="Default route found but could not parse gateway",
                raw_output=output,
            )

        # Check if ANY gateway matches (ECMP support)
        if gateway in matches:
            return ValidationResult(
                passed=True,
                message=f"Default route exists via {gateway}",
                raw_output=output,
            )
        else:
            return ValidationResult(
                passed=False,
                message=(
                    f"Default route gateway mismatch: "
                    f"expected {gateway}, got {', '.join(matches)}"
                ),
                raw_output=output,
            )
    else:
        return ValidationResult(
            passed=True,
            message="Default route exists",
            raw_output=output,
        )


def check_snat_rule(
    ssh: Callable[[str], str],
    rule_num: int,
    outbound_interface: str | None = None,
    translation: str | None = None,
) -> ValidationResult:
    """Verify a source NAT rule exists with expected parameters.

    This function checks the VyOS configuration for a specific SNAT rule
    and validates its outbound interface and translation address if provided.

    VyOS Output Format:
        show configuration commands | grep "nat source"
        Returns output like:
            set nat source rule 100 outbound-interface name 'eth0'
            set nat source rule 100 source address '10.0.0.0/24'
            set nat source rule 100 translation address 'masquerade'

    Args:
        ssh: SSH connection callable from ssh_connection fixture
        rule_num: NAT rule number to check
        outbound_interface: Expected outbound interface (optional)
        translation: Expected translation address or 'masquerade' (optional)

    Returns:
        ValidationResult indicating whether SNAT rule matches expectations
    """
    try:
        output = ssh("show configuration commands | grep 'nat source'")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query NAT source rules: {e}",
            raw_output="",
        )

    # Filter lines for the specific rule number
    rule_pattern = re.compile(rf"set nat source rule {rule_num}\s+(.+)")
    rule_lines = [line for line in output.splitlines() if rule_pattern.match(line)]

    if not rule_lines:
        return ValidationResult(
            passed=False,
            message=f"SNAT rule {rule_num} not found in configuration",
            raw_output=output,
        )

    # Join all rule lines for this rule number
    rule_config = "\n".join(rule_lines)

    # Check outbound interface if specified
    if outbound_interface is not None:
        escaped_iface = re.escape(outbound_interface)
        interface_pattern = re.compile(
            rf"set nat source rule {rule_num} outbound-interface name \'?{escaped_iface}\'?"
        )
        if not interface_pattern.search(rule_config):
            return ValidationResult(
                passed=False,
                message=(
                    f"SNAT rule {rule_num} outbound interface mismatch: "
                    f"expected '{outbound_interface}'"
                ),
                raw_output=rule_config,
            )

    # Check translation if specified
    if translation is not None:
        translation_pattern = re.compile(
            rf"set nat source rule {rule_num} translation address \'?{re.escape(translation)}\'?"
        )
        if not translation_pattern.search(rule_config):
            return ValidationResult(
                passed=False,
                message=f"SNAT rule {rule_num} translation mismatch: expected '{translation}'",
                raw_output=rule_config,
            )

    # All checks passed
    checks = []
    if outbound_interface is not None:
        checks.append(f"outbound-interface={outbound_interface}")
    if translation is not None:
        checks.append(f"translation={translation}")

    check_str = ", ".join(checks) if checks else "exists"
    return ValidationResult(
        passed=True,
        message=f"SNAT rule {rule_num} validated: {check_str}",
        raw_output=rule_config,
    )


def check_dnat_rule(
    ssh: Callable[[str], str],
    rule_num: int,
    inbound_interface: str | None = None,
    protocol: str | None = None,
    port: str | None = None,
    translation_address: str | None = None,
    translation_port: str | None = None,
) -> ValidationResult:
    """Verify a destination NAT rule exists with expected parameters.

    This function checks the VyOS configuration for a specific DNAT rule
    and validates its parameters if provided.

    VyOS Output Format:
        show configuration commands | grep "nat destination"
        Returns output like:
            set nat destination rule 10 inbound-interface name 'eth0'
            set nat destination rule 10 destination port '80'
            set nat destination rule 10 protocol 'tcp'
            set nat destination rule 10 translation address '192.168.1.10'
            set nat destination rule 10 translation port '8080'

    Args:
        ssh: SSH connection callable from ssh_connection fixture
        rule_num: NAT rule number to check
        inbound_interface: Expected inbound interface (optional)
        protocol: Expected protocol (tcp/udp) (optional)
        port: Expected destination port (optional)
        translation_address: Expected translation IP address (optional)
        translation_port: Expected translation port (optional)

    Returns:
        ValidationResult indicating whether DNAT rule matches expectations
    """
    try:
        output = ssh("show configuration commands | grep 'nat destination'")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query NAT destination rules: {e}",
            raw_output="",
        )

    # Filter lines for the specific rule number
    rule_pattern = re.compile(rf"set nat destination rule {rule_num}\s+(.+)")
    rule_lines = [line for line in output.splitlines() if rule_pattern.match(line)]

    if not rule_lines:
        return ValidationResult(
            passed=False,
            message=f"DNAT rule {rule_num} not found in configuration",
            raw_output=output,
        )

    # Join all rule lines for this rule number
    rule_config = "\n".join(rule_lines)

    # Check inbound interface if specified
    if inbound_interface is not None:
        escaped_iface = re.escape(inbound_interface)
        interface_pattern = re.compile(
            rf"set nat destination rule {rule_num} inbound-interface name \'?{escaped_iface}\'?"
        )
        if not interface_pattern.search(rule_config):
            return ValidationResult(
                passed=False,
                message=(
                    f"DNAT rule {rule_num} inbound interface mismatch: "
                    f"expected '{inbound_interface}'"
                ),
                raw_output=rule_config,
            )

    # Check protocol if specified
    if protocol is not None:
        protocol_pattern = re.compile(
            rf"set nat destination rule {rule_num} protocol \'?{re.escape(protocol)}\'?"
        )
        if not protocol_pattern.search(rule_config):
            return ValidationResult(
                passed=False,
                message=f"DNAT rule {rule_num} protocol mismatch: expected '{protocol}'",
                raw_output=rule_config,
            )

    # Check port if specified
    if port is not None:
        port_pattern = re.compile(
            rf"set nat destination rule {rule_num} destination port \'?{re.escape(port)}\'?"
        )
        if not port_pattern.search(rule_config):
            return ValidationResult(
                passed=False,
                message=f"DNAT rule {rule_num} port mismatch: expected '{port}'",
                raw_output=rule_config,
            )

    # Check translation address if specified
    if translation_address is not None:
        escaped_addr = re.escape(translation_address)
        translation_pattern = re.compile(
            rf"set nat destination rule {rule_num} translation address \'?{escaped_addr}\'?"
        )
        if not translation_pattern.search(rule_config):
            return ValidationResult(
                passed=False,
                message=(
                    f"DNAT rule {rule_num} translation address mismatch: "
                    f"expected '{translation_address}'"
                ),
                raw_output=rule_config,
            )

    # Check translation port if specified
    if translation_port is not None:
        escaped_port = re.escape(translation_port)
        port_pattern = re.compile(
            rf"set nat destination rule {rule_num} translation port \'?{escaped_port}\'?"
        )
        if not port_pattern.search(rule_config):
            return ValidationResult(
                passed=False,
                message=(
                    f"DNAT rule {rule_num} translation port mismatch: "
                    f"expected '{translation_port}'"
                ),
                raw_output=rule_config,
            )

    # All checks passed
    checks = []
    if inbound_interface is not None:
        checks.append(f"inbound-interface={inbound_interface}")
    if protocol is not None:
        checks.append(f"protocol={protocol}")
    if port is not None:
        checks.append(f"port={port}")
    if translation_address is not None:
        checks.append(f"translation={translation_address}")
    if translation_port is not None:
        checks.append(f"translation_port={translation_port}")

    check_str = ", ".join(checks) if checks else "exists"
    return ValidationResult(
        passed=True,
        message=f"DNAT rule {rule_num} validated: {check_str}",
        raw_output=rule_config,
    )


def list_nat_rules(
    ssh: Callable[[str], str],
    nat_type: str,
) -> ValidationResult:
    """List all NAT rules of the specified type.

    This function retrieves all NAT rules for a given type (source or destination)
    from the VyOS configuration. Useful for debugging and verifying rule sets.

    VyOS Output Format:
        show configuration commands | grep "nat source"
        or
        show configuration commands | grep "nat destination"

    Args:
        ssh: SSH connection callable from ssh_connection fixture
        nat_type: Type of NAT rules to list ("source" or "destination")

    Returns:
        ValidationResult with all NAT rules of the specified type
    """
    if nat_type not in ("source", "destination"):
        return ValidationResult(
            passed=False,
            message=f"Invalid nat_type '{nat_type}': must be 'source' or 'destination'",
            raw_output="",
        )

    try:
        output = ssh(f"show configuration commands | grep 'nat {nat_type}'")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query NAT {nat_type} rules: {e}",
            raw_output="",
        )

    # Extract rule numbers from the output
    rule_pattern = re.compile(rf"set nat {nat_type} rule (\d+)")
    rule_numbers = sorted({int(m.group(1)) for m in rule_pattern.finditer(output)})

    if not rule_numbers:
        return ValidationResult(
            passed=True,
            message=f"No NAT {nat_type} rules configured",
            raw_output=output,
        )

    return ValidationResult(
        passed=True,
        message=f"Found {len(rule_numbers)} NAT {nat_type} rule(s): {rule_numbers}",
        raw_output=output,
    )


def check_vrf_exists(
    ssh: Callable[[str], str],
    vrf_name: str,
    table_id: int | None = None,
) -> ValidationResult:
    """Verify a VRF exists with optional table ID validation.

    This function checks whether a VRF is configured in VyOS and optionally
    validates that it has the expected routing table ID.

    VyOS Output Format:
        show vrf
        Returns output like:
            VRF name          state     mac address        flags                     interfaces
            --------          -----     -----------        -----                     ----------
            mgmt              up        aa:bb:cc:dd:ee:ff  noarp,master,up,lower_up  eth0

        Or with more detail:
            show vrf name mgmt
            Returns:
                VRF: mgmt
                  Table: 1000
                  Interfaces:
                    eth0

    Args:
        ssh: SSH connection callable from ssh_connection fixture
        vrf_name: Name of the VRF to check (e.g., "mgmt")
        table_id: Optional routing table ID to validate (e.g., 1000)

    Returns:
        ValidationResult indicating whether VRF exists and matches table ID if specified
    """
    try:
        # First check if VRF exists in the VRF list
        output = ssh("show vrf")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query VRF list: {e}",
            raw_output="",
        )

    # Look for VRF name in the output
    # VRF names appear at the start of lines (after header)
    vrf_pattern = re.compile(rf"^{re.escape(vrf_name)}\s+", re.MULTILINE)
    if not vrf_pattern.search(output):
        return ValidationResult(
            passed=False,
            message=f"VRF '{vrf_name}' not found in VRF list",
            raw_output=output,
        )

    # If table_id validation is requested, get detailed VRF info
    if table_id is not None:
        try:
            detail_output = ssh(f"show vrf name {vrf_name}")
        except Exception as e:
            return ValidationResult(
                passed=False,
                message=f"Failed to query VRF '{vrf_name}' details: {e}",
                raw_output=output,
            )

        # Look for "Table: <id>" in the detailed output
        table_pattern = re.compile(r"Table:\s+(\d+)")
        table_match = table_pattern.search(detail_output)

        if not table_match:
            return ValidationResult(
                passed=False,
                message=f"VRF '{vrf_name}' exists but table ID not found in details",
                raw_output=f"{output}\n\n{detail_output}",
            )

        actual_table_id = int(table_match.group(1))

        if actual_table_id != table_id:
            return ValidationResult(
                passed=False,
                message=(
                    f"VRF '{vrf_name}' table ID mismatch: "
                    f"expected {table_id}, got {actual_table_id}"
                ),
                raw_output=f"{output}\n\n{detail_output}",
            )

        return ValidationResult(
            passed=True,
            message=f"VRF '{vrf_name}' exists with table ID {table_id}",
            raw_output=f"{output}\n\n{detail_output}",
        )

    # No table_id validation requested, just confirm VRF exists
    return ValidationResult(
        passed=True,
        message=f"VRF '{vrf_name}' exists",
        raw_output=output,
    )


def check_vrf_interface(
    ssh: Callable[[str], str],
    vrf_name: str,
    interface: str,
) -> ValidationResult:
    """Verify an interface is bound to a VRF.

    This function checks whether a specific interface is assigned to the
    specified VRF by examining the VRF details via 'show vrf name <vrf>'.

    VyOS Output Format:
        show vrf name mgmt
        Returns:
            VRF: mgmt
              Table: 1000
              Interfaces:
                eth0

    Note: An alternative approach would be to query the interface directly
    via 'show interfaces ethernet <interface>' and check for VRF membership
    in the output. This is not currently implemented but could be added
    if needed for cases where VRF details are unavailable.

    Args:
        ssh: SSH connection callable from ssh_connection fixture
        vrf_name: Name of the VRF (e.g., "mgmt")
        interface: Interface name (e.g., "eth0")

    Returns:
        ValidationResult indicating whether interface is bound to VRF
    """
    try:
        # Check VRF details for the interface
        output = ssh(f"show vrf name {vrf_name}")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query VRF '{vrf_name}': {e}",
            raw_output="",
        )

    # Look for the interface in the VRF's interface list
    # Format: interface names appear under "Interfaces:" section
    # Check if interface appears after "Interfaces:" line
    interfaces_section_pattern = re.compile(
        r"Interfaces:\s*\n((?:\s+\S+\s*(?:\n|$))*)",
        re.MULTILINE,
    )
    interfaces_match = interfaces_section_pattern.search(output)

    if not interfaces_match:
        return ValidationResult(
            passed=False,
            message=f"VRF '{vrf_name}' exists but has no interfaces listed",
            raw_output=output,
        )

    interfaces_text = interfaces_match.group(1)

    # Check if our interface appears in the interfaces list
    # Interfaces are indented and each on their own line
    # Use regex to match whole interface name on its own line to avoid false positives
    # (e.g., "eth0" should not match "eth00")
    interface_line_pattern = re.compile(rf"^\s*{re.escape(interface)}\s*$", re.MULTILINE)
    if interface_line_pattern.search(interfaces_text):
        return ValidationResult(
            passed=True,
            message=f"Interface {interface} is bound to VRF '{vrf_name}'",
            raw_output=output,
        )
    else:
        return ValidationResult(
            passed=False,
            message=f"Interface {interface} not found in VRF '{vrf_name}'",
            raw_output=output,
        )


def check_service_vrf(
    ssh: Callable[[str], str],
    service: str,
    vrf_name: str,
) -> ValidationResult:
    """Verify a service is bound to a VRF.

    This function checks whether a VyOS service (like SSH) is configured
    to run within a specific VRF by examining the service configuration.

    VyOS Output Format:
        show configuration commands | grep "service ssh vrf"
        Returns:
            set service ssh vrf 'mgmt'

        Or for other services:
            set service https vrf 'mgmt'

    Args:
        ssh: SSH connection callable from ssh_connection fixture
        service: Service name (e.g., "ssh", "https", "snmp")
        vrf_name: VRF name the service should be bound to (e.g., "mgmt")

    Returns:
        ValidationResult indicating whether service is bound to VRF
    """
    try:
        # Query configuration for service VRF binding
        # Use || echo '' to avoid error if no match found
        output = ssh(f"show configuration commands | grep 'service {service} vrf' || echo ''")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query service '{service}' VRF configuration: {e}",
            raw_output="",
        )

    # Look for "set service <service> vrf '<vrf_name>'" or "set service <service> vrf <vrf_name>"
    # Match with proper quote pairing to avoid accepting mixed quotes like 'mgmt"
    vrf_pattern = re.compile(
        rf"set\s+service\s+{re.escape(service)}\s+vrf\s+(?:'{re.escape(vrf_name)}'|\"{re.escape(vrf_name)}\"|{re.escape(vrf_name)}\b)",
    )
    match = vrf_pattern.search(output)

    if match:
        return ValidationResult(
            passed=True,
            message=f"Service '{service}' is bound to VRF '{vrf_name}'",
            raw_output=output,
        )
    elif not output.strip():
        return ValidationResult(
            passed=False,
            message=f"Service '{service}' has no VRF binding configured",
            raw_output=output,
        )
    else:
        # Service has a VRF binding, but it's not the expected one
        # Try to extract what VRF it's bound to
        any_vrf_pattern = re.compile(
            rf"set\s+service\s+{re.escape(service)}\s+vrf\s+['\"]?(\S+?)['\"]?(?:\s|$)",
        )
        any_match = any_vrf_pattern.search(output)

        if any_match:
            actual_vrf = any_match.group(1).strip("'\"")
            return ValidationResult(
                passed=False,
                message=(
                    f"Service '{service}' VRF mismatch: "
                    f"expected '{vrf_name}', got '{actual_vrf}'"
                ),
                raw_output=output,
            )
        else:
            return ValidationResult(
                passed=False,
                message=f"Service '{service}' VRF configuration found but cannot parse VRF name",
                raw_output=output,
            )
