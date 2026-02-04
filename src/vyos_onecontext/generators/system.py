"""System configuration generators (hostname, SSH keys, conntrack)."""

import re

from vyos_onecontext.generators.base import BaseGenerator
from vyos_onecontext.models.system import ConntrackConfig


class HostnameGenerator(BaseGenerator):
    """Generate VyOS hostname configuration commands."""

    def __init__(self, hostname: str | None):
        """Initialize hostname generator.

        Args:
            hostname: System hostname to configure, or None to skip
        """
        self.hostname = hostname

    def generate(self) -> list[str]:
        """Generate hostname configuration command.

        Returns:
            List with hostname command if hostname is set, empty list otherwise
        """
        if self.hostname is None:
            return []

        return [f"set system host-name {self.hostname}"]


class SshKeyGenerator(BaseGenerator):
    """Generate VyOS SSH public key configuration commands."""

    def __init__(self, ssh_public_key: str | None):
        """Initialize SSH key generator.

        Args:
            ssh_public_key: SSH public key in format "type key comment", or None to skip
        """
        self.ssh_public_key = ssh_public_key

    def generate(self) -> list[str]:
        """Generate SSH public key configuration commands.

        Parses the SSH key format (type key comment) and generates VyOS commands
        to configure it for the vyos user. Supports multiple newline-separated keys.

        Returns:
            List with SSH key commands if key is set, empty list otherwise
        """
        if self.ssh_public_key is None:
            return []

        commands = []
        key_configs = []
        key_counter = 1  # Track processed keys to generate unique IDs
        seen_key_ids: set[str] = set()  # Track used key IDs to avoid duplicates

        # Split on newlines to handle multiple keys
        for key_line in self.ssh_public_key.strip().split("\n"):
            key_line = key_line.strip()
            if not key_line:
                continue

            # Parse SSH key format: "type key comment"
            # Example: "ssh-rsa AAAAB3NzaC1yc2E... user@host"
            parts = key_line.split(None, 2)

            if len(parts) < 2:
                # Invalid key format - skip this key
                continue

            key_type = parts[0]
            key_data = parts[1]

            # Use comment as identifier if available, otherwise use "keyN"
            if len(parts) >= 3:
                key_id = parts[2]
            else:
                key_id = f"key{key_counter}"
                key_counter += 1  # Only increment when counter is used

            # Sanitize key_id for use as VyOS identifier
            # VyOS only accepts alphanumeric characters and underscores
            # Strip surrounding quotes (single or double) that may be in the comment
            key_id = key_id.strip("\"'")
            # Replace @ with _at_ for better readability
            key_id = key_id.replace("@", "_at_")
            # Replace all other non-alphanumeric characters (except underscores) with underscores
            key_id = re.sub(r"[^a-zA-Z0-9_]", "_", key_id)

            # Handle duplicate key IDs by appending a suffix
            base_key_id = key_id
            dup_counter = 2
            while key_id in seen_key_ids:
                key_id = f"{base_key_id}_{dup_counter}"
                dup_counter += 1
            seen_key_ids.add(key_id)

            # Configure the public key for authentication
            key_configs.append(
                f"set system login user vyos authentication public-keys {key_id} key {key_data}"
            )
            key_configs.append(
                f"set system login user vyos authentication public-keys {key_id} type {key_type}"
            )

        # Only enable SSH service if we have at least one valid key
        if key_configs:
            commands.append("set service ssh port 22")
            commands.extend(key_configs)

        return commands


class ConntrackGenerator(BaseGenerator):
    """Generate VyOS conntrack timeout configuration commands."""

    def __init__(self, conntrack: ConntrackConfig | None):
        """Initialize conntrack generator.

        Args:
            conntrack: Conntrack configuration (None if not configured)
        """
        self.conntrack = conntrack

    def generate(self) -> list[str]:
        """Generate conntrack timeout configuration commands.

        Returns:
            List of VyOS 'set' commands for conntrack timeout rules
        """
        commands: list[str] = []

        if self.conntrack is None:
            return commands

        for idx, rule in enumerate(self.conntrack.timeout_rules, start=1):
            rule_num = idx

            # Description (optional)
            if rule.description:
                commands.append(
                    f"set system conntrack timeout custom ipv4 rule {rule_num} "
                    f"description '{rule.description}'"
                )

            # Source address (optional)
            if rule.source_address:
                commands.append(
                    f"set system conntrack timeout custom ipv4 rule {rule_num} "
                    f"source address {rule.source_address}"
                )

            # Destination address (optional)
            if rule.destination_address:
                commands.append(
                    f"set system conntrack timeout custom ipv4 rule {rule_num} "
                    f"destination address {rule.destination_address}"
                )

            # Protocol (required)
            commands.append(
                f"set system conntrack timeout custom ipv4 rule {rule_num} "
                f"protocol {rule.protocol}"
            )

            # Protocol-specific timeouts
            if rule.protocol == "tcp":
                if rule.tcp_close is not None:
                    commands.append(
                        f"set system conntrack timeout custom ipv4 rule {rule_num} "
                        f"protocol tcp close {rule.tcp_close}"
                    )
                if rule.tcp_close_wait is not None:
                    commands.append(
                        f"set system conntrack timeout custom ipv4 rule {rule_num} "
                        f"protocol tcp close-wait {rule.tcp_close_wait}"
                    )
                if rule.tcp_established is not None:
                    commands.append(
                        f"set system conntrack timeout custom ipv4 rule {rule_num} "
                        f"protocol tcp established {rule.tcp_established}"
                    )
                if rule.tcp_fin_wait is not None:
                    commands.append(
                        f"set system conntrack timeout custom ipv4 rule {rule_num} "
                        f"protocol tcp fin-wait {rule.tcp_fin_wait}"
                    )
                if rule.tcp_last_ack is not None:
                    commands.append(
                        f"set system conntrack timeout custom ipv4 rule {rule_num} "
                        f"protocol tcp last-ack {rule.tcp_last_ack}"
                    )
                if rule.tcp_syn_recv is not None:
                    commands.append(
                        f"set system conntrack timeout custom ipv4 rule {rule_num} "
                        f"protocol tcp syn-recv {rule.tcp_syn_recv}"
                    )
                if rule.tcp_syn_sent is not None:
                    commands.append(
                        f"set system conntrack timeout custom ipv4 rule {rule_num} "
                        f"protocol tcp syn-sent {rule.tcp_syn_sent}"
                    )
                if rule.tcp_time_wait is not None:
                    commands.append(
                        f"set system conntrack timeout custom ipv4 rule {rule_num} "
                        f"protocol tcp time-wait {rule.tcp_time_wait}"
                    )
            elif rule.protocol == "udp":
                if rule.udp_other is not None:
                    commands.append(
                        f"set system conntrack timeout custom ipv4 rule {rule_num} "
                        f"protocol udp other {rule.udp_other}"
                    )
                if rule.udp_stream is not None:
                    commands.append(
                        f"set system conntrack timeout custom ipv4 rule {rule_num} "
                        f"protocol udp stream {rule.udp_stream}"
                    )
            elif rule.protocol == "icmp":
                if rule.icmp_timeout is not None:
                    commands.append(
                        f"set system conntrack timeout custom ipv4 rule {rule_num} "
                        f"icmp {rule.icmp_timeout}"
                    )

        return commands
