"""System configuration generators (hostname, SSH keys)."""

from vyos_onecontext.generators.base import BaseGenerator


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
        to configure it for the vyos user.

        Returns:
            List with SSH key commands if key is set, empty list otherwise
        """
        if self.ssh_public_key is None:
            return []

        # Parse SSH key format: "type key comment"
        # Example: "ssh-rsa AAAAB3NzaC1yc2E... user@host"
        parts = self.ssh_public_key.strip().split(None, 2)

        if len(parts) < 2:
            # Invalid key format - skip configuration
            return []

        key_type = parts[0]
        key_data = parts[1]

        # Use comment as identifier if available, otherwise use "key1"
        key_id = parts[2] if len(parts) >= 3 else "key1"
        # Sanitize key_id for use as VyOS identifier (replace spaces with underscores)
        key_id = key_id.replace(" ", "_")

        return [
            # Enable SSH service (required since base config is wiped)
            "set service ssh port 22",
            # Configure the public key for authentication
            f"set system login user vyos authentication public-keys {key_id} key {key_data}",
            f"set system login user vyos authentication public-keys {key_id} type {key_type}",
        ]
