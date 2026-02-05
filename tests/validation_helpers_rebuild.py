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
- show configuration commands | grep public-keys: Returns SSH key config
- show ip ospf: Shows OSPF instance status including router ID
- show configuration commands | grep ospf: Shows OSPF config commands
- show ip route: Returns routing table with protocol codes and next-hop info
- show configuration commands | grep 'nat source': Returns NAT source set commands
- show configuration commands | grep 'nat destination': Returns NAT dest set commands
- show vrf: Shows VRF list and details
- show service dhcp-server: Shows DHCP server status and lease information
- show configuration commands | grep dhcp-server: Shows DHCP configuration
"""

