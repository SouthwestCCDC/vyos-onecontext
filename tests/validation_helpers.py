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
- show configuration commands | grep 'set system login user vyos authentication public-keys':
  Returns public-keys stanzas if configured
- show ip ospf: Shows OSPF instance status including router ID
- show configuration commands | grep ospf: Shows OSPF config commands
- show service dhcp-server: Shows DHCP server status and lease information
- show configuration commands | grep dhcp-server: Shows DHCP configuration
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
    # Use findall() to collect all IPs since interfaces can have multiple IPs
    ip_pattern = re.compile(r"inet\s+(\d+\.\d+\.\d+\.\d+)/\d+")
    matches = ip_pattern.findall(output)

    if not matches:
        return ValidationResult(
            passed=False,
            message=f"No IP address found on interface {interface}",
            raw_output=output,
        )

    # Check if expected IP is in the list of found IPs
    if expected_ip in matches:
        return ValidationResult(
            passed=True,
            message=f"Interface {interface} has expected IP {expected_ip}",
            raw_output=output,
        )
    else:
        return ValidationResult(
            passed=False,
            message=f"IP mismatch on {interface}: expected {expected_ip}, got {', '.join(matches)}",
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
        output = ssh("show configuration | grep host-name || true")
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
        show configuration commands | grep 'set system login user vyos authentication public-keys'
        Returns output like:
            set system login user vyos authentication public-keys test-key-1 key 'AAAAB3Nza...'
            set system login user vyos authentication public-keys test-key-1 type 'ssh-rsa'

    Args:
        ssh: SSH connection callable from ssh_connection fixture

    Returns:
        ValidationResult indicating whether SSH keys are configured
    """
    try:
        output = ssh(
            "show configuration commands | "
            "grep 'set system login user vyos authentication public-keys' || echo ''"
        )
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


def check_dhcp_server_running(
    ssh: Callable[[str], str],
) -> ValidationResult:
    """Verify DHCP server process is active.

    This function checks if the DHCP server is running by querying the
    service status via VyOS operational commands.

    VyOS Output Format:
        show service dhcp-server
        Returns output like:
            DHCP server listening on:
                eth1

            Pool: dhcp-eth1
                Failover state: N/A
                Status: active
                Leases: 5
                Available: 95

    Args:
        ssh: SSH connection callable from ssh_connection fixture

    Returns:
        ValidationResult indicating whether DHCP server is running
    """
    try:
        output = ssh("show service dhcp-server")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query DHCP server status: {e}",
            raw_output="",
        )

    # Check if DHCP server is listening on any interfaces
    # Look for "DHCP server listening on:" or "Pool:" in output
    if "listening on:" in output.lower() or "pool:" in output.lower():
        return ValidationResult(
            passed=True,
            message="DHCP server is running",
            raw_output=output,
        )
    else:
        # Check if output indicates service is not configured
        if "not configured" in output.lower() or output.strip() == "":
            return ValidationResult(
                passed=False,
                message="DHCP server is not configured or not running",
                raw_output=output,
            )
        else:
            # Unknown output format
            return ValidationResult(
                passed=False,
                message="Unable to determine DHCP server status from output",
                raw_output=output,
            )


def check_dhcp_pool(
    ssh: Callable[[str], str],
    network_name: str,
    subnet: str | None,
) -> ValidationResult:
    """Verify DHCP pool exists in configuration.

    This function checks that a DHCP shared-network exists and optionally
    validates that it contains the expected subnet.

    VyOS Output Format:
        show configuration commands | grep dhcp-server
        Returns output like:
            set service dhcp-server shared-network-name dhcp-eth1 subnet 10.1.1.0/24 \
                range 0 start 10.1.1.100
            set service dhcp-server shared-network-name dhcp-eth1 subnet 10.1.1.0/24 \
                range 0 stop 10.1.1.200

    Args:
        ssh: SSH connection callable from ssh_connection fixture
        network_name: Shared-network name (e.g., "dhcp-eth1")
        subnet: Expected subnet in CIDR notation (e.g., "10.1.1.0/24"), None to skip check

    Returns:
        ValidationResult indicating whether DHCP pool exists and matches expectations
    """
    try:
        output = ssh("show configuration commands | grep dhcp-server || true")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query DHCP server configuration: {e}",
            raw_output="",
        )

    # Check if the shared-network-name exists in configuration
    # Handle optional quotes around network_name (VyOS may quote values)
    network_pattern = re.compile(rf"shared-network-name\s+'?{re.escape(network_name)}'?\s+subnet")
    network_matches = network_pattern.search(output)

    if not network_matches:
        return ValidationResult(
            passed=False,
            message=f"DHCP shared-network '{network_name}' not found in configuration",
            raw_output=output,
        )

    # If subnet is provided, verify it matches
    if subnet is not None:
        # Handle optional quotes around network_name and subnet
        subnet_pattern = re.compile(
            rf"shared-network-name\s+'?{re.escape(network_name)}'?\s+subnet\s+'?{re.escape(subnet)}'?\s+"
        )
        subnet_matches = subnet_pattern.search(output)

        if not subnet_matches:
            return ValidationResult(
                passed=False,
                message=f"DHCP pool '{network_name}' found but subnet '{subnet}' not configured",
                raw_output=output,
            )

        return ValidationResult(
            passed=True,
            message=f"DHCP pool '{network_name}' exists with subnet '{subnet}'",
            raw_output=output,
        )
    else:
        return ValidationResult(
            passed=True,
            message=f"DHCP pool '{network_name}' exists",
            raw_output=output,
        )


def check_dhcp_options(
    ssh: Callable[[str], str],
    network_name: str,
    default_router: str | None,
    dns_servers: list[str] | None,
) -> ValidationResult:
    """Verify DHCP options are configured correctly.

    This function checks that DHCP options (default-router, DNS servers)
    are configured for the specified shared-network.

    VyOS Output Format:
        show configuration commands | grep dhcp-server
        Returns output like:
            set service dhcp-server shared-network-name dhcp-eth1 subnet 10.1.1.0/24 \
                default-router 10.1.1.1
            set service dhcp-server shared-network-name dhcp-eth1 subnet 10.1.1.0/24 \
                name-server 10.63.4.101

    Args:
        ssh: SSH connection callable from ssh_connection fixture
        network_name: Shared-network name (e.g., "dhcp-eth1")
        default_router: Expected default gateway IP (None to skip check)
        dns_servers: Expected DNS server IPs (None to skip check)

    Returns:
        ValidationResult indicating whether DHCP options match expectations
    """
    try:
        output = ssh("show configuration commands | grep dhcp-server || true")
    except Exception as e:
        return ValidationResult(
            passed=False,
            message=f"Failed to query DHCP server configuration: {e}",
            raw_output="",
        )

    # Build list of failed checks
    failures = []

    # Check if the shared-network-name exists in configuration
    # Handle optional quotes around network_name (VyOS may quote values)
    network_pattern = re.compile(rf"shared-network-name\s+'?{re.escape(network_name)}'?\s+subnet")
    if not network_pattern.search(output):
        return ValidationResult(
            passed=False,
            message=f"DHCP shared-network '{network_name}' not found in configuration",
            raw_output=output,
        )

    # Check default-router if provided
    if default_router is not None:
        # Handle optional quotes around network_name, subnet, and default_router
        router_pattern = re.compile(
            rf"shared-network-name\s+'?{re.escape(network_name)}'?\s+subnet\s+\S+\s+default-router\s+'?{re.escape(default_router)}'?"
        )
        if not router_pattern.search(output):
            failures.append(f"default-router '{default_router}' not found")

    # Check DNS servers if provided
    # Note: Empty list ([]) means skip DNS check (same as None)
    if dns_servers is not None and len(dns_servers) > 0:
        for dns in dns_servers:
            # Handle optional quotes around network_name and dns server
            dns_pattern = re.compile(
                rf"shared-network-name\s+'?{re.escape(network_name)}'?\s+subnet\s+\S+\s+name-server\s+'?{re.escape(dns)}'?"
            )
            if not dns_pattern.search(output):
                failures.append(f"name-server '{dns}' not found")

    # Return result
    if failures:
        return ValidationResult(
            passed=False,
            message=f"DHCP options for '{network_name}' incomplete: {', '.join(failures)}",
            raw_output=output,
        )
    else:
        options_checked = []
        if default_router is not None:
            options_checked.append(f"default-router={default_router}")
        if dns_servers is not None and len(dns_servers) > 0:
            options_checked.append(f"dns={','.join(dns_servers)}")

        if options_checked:
            return ValidationResult(
                passed=True,
                message=f"DHCP options for '{network_name}' correct: {'; '.join(options_checked)}",
                raw_output=output,
            )
        else:
            return ValidationResult(
                passed=True,
                message=f"DHCP shared-network '{network_name}' exists (no options checked)",
                raw_output=output,
            )
