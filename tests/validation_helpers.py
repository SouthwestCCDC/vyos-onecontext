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
- show vrf: Lists VRFs with their table IDs and member interfaces
- show configuration commands | grep "service ... vrf": Shows VRF bindings for services
"""

import re
from collections.abc import Callable
from dataclasses import dataclass

# Security validation functions to prevent command injection
# These must be called before interpolating user inputs into shell commands


def _validate_vrf_name(vrf_name: str) -> None:
    """Validate VRF name to prevent command injection.

    VRF names in VyOS must:
    - Start with a letter
    - Contain only alphanumeric characters, hyphens, and underscores
    - Not be empty

    Args:
        vrf_name: VRF name to validate

    Raises:
        ValueError: If VRF name contains invalid characters or format
    """
    if not vrf_name:
        raise ValueError("VRF name cannot be empty")

    # VRF names must start with a letter and contain only safe characters
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*$", vrf_name):
        raise ValueError(
            f"Invalid VRF name '{vrf_name}': must start with a letter and "
            "contain only alphanumeric characters, hyphens, and underscores"
        )


def _validate_interface_name(interface: str) -> None:
    """Validate interface name to prevent command injection.

    VyOS interface names follow patterns like:
    - eth0, eth1 (ethernet)
    - eth0.100 (VLAN subinterface)
    - eth0@eth1 (macvlan)
    - bond0, bond1 (bonding)
    - br0, br1 (bridge)

    Args:
        interface: Interface name to validate

    Raises:
        ValueError: If interface name contains invalid characters or format
    """
    if not interface:
        raise ValueError("Interface name cannot be empty")

    # Interface names must start with a letter and may contain dots, @, colons, hyphens
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9._@:-]*$", interface):
        raise ValueError(
            f"Invalid interface name '{interface}': must start with a letter and "
            "contain only alphanumeric characters and . _ @ : -"
        )


def _validate_service_name(service: str) -> None:
    """Validate service name to prevent command injection.

    Only allow known VyOS services to prevent injection attacks.

    Args:
        service: Service name to validate

    Raises:
        ValueError: If service name is not in the whitelist
    """
    # Whitelist of valid VyOS services that support VRF binding
    VALID_SERVICES = {
        "ssh",
        "https",
        "http",
        "snmp",
        "ntp",
        "dns",
        "dhcp-server",
        "dhcpv6-server",
        "router-advert",
        "mdns",
        "lldp",
        "console-server",
        "monitoring",
        "ids",
        "ipsec",
        "nat",
        "pppoe-server",
        "pptp",
        "sstp",
        "tftp-server",
        "suricata",
        "telegraf",
    }

    if service not in VALID_SERVICES:
        raise ValueError(
            f"Invalid service name '{service}': must be one of {sorted(VALID_SERVICES)}"
        )


def _validate_ip_address(ip: str) -> None:
    """Validate IPv4 address format and ranges.

    Ensures IP address:
    - Matches dotted decimal format
    - All octets are in range 0-255

    Args:
        ip: IP address string to validate

    Raises:
        ValueError: If IP address format is invalid or octets out of range
    """
    if not ip:
        raise ValueError("IP address cannot be empty")

    # First check basic format with regex
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        raise ValueError(f"Invalid IP address format: '{ip}'")

    # Validate each octet is in range 0-255
    octets = ip.split(".")
    for i, octet in enumerate(octets):
        value = int(octet)
        if not 0 <= value <= 255:
            raise ValueError(
                f"Invalid IP address '{ip}': octet {i + 1} ({value}) out of range 0-255"
            )


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
    # Validate inputs to prevent command injection
    _validate_interface_name(interface)
    _validate_ip_address(expected_ip)

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
    # Validate inputs to prevent command injection
    _validate_interface_name(interface)

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
    # Validate inputs to prevent command injection
    _validate_vrf_name(vrf_name)

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
    # Validate inputs to prevent command injection
    _validate_vrf_name(vrf_name)
    _validate_interface_name(interface)

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
    # Validate inputs to prevent command injection
    _validate_service_name(service)
    _validate_vrf_name(vrf_name)

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
