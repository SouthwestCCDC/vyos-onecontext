"""Tests for VyOS command generators."""

from ipaddress import IPv4Address

from vyos_onecontext.generators import (
    HostnameGenerator,
    InterfaceGenerator,
    SshKeyGenerator,
    generate_config,
)
from vyos_onecontext.models import AliasConfig, InterfaceConfig, RouterConfig


class TestHostnameGenerator:
    """Tests for hostname configuration generator."""

    def test_generate_with_hostname(self):
        """Test hostname generation with valid hostname."""
        gen = HostnameGenerator("router-01")
        commands = gen.generate()

        assert len(commands) == 1
        assert commands[0] == "set system host-name 'router-01'"

    def test_generate_without_hostname(self):
        """Test hostname generation with None hostname."""
        gen = HostnameGenerator(None)
        commands = gen.generate()

        assert len(commands) == 0


class TestSshKeyGenerator:
    """Tests for SSH key configuration generator."""

    def test_generate_with_rsa_key(self):
        """Test SSH key generation with RSA key."""
        key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... user@host"
        gen = SshKeyGenerator(key)
        commands = gen.generate()

        assert len(commands) == 2
        assert (
            "set system login user vyos authentication public-keys "
            "user@host key 'AAAAB3NzaC1yc2EAAAADAQABAAABAQC...'"
        ) in commands[0]
        assert (
            "set system login user vyos authentication public-keys "
            "user@host type ssh-rsa"
        ) in commands[1]

    def test_generate_with_ed25519_key(self):
        """Test SSH key generation with ED25519 key."""
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... admin@example.com"
        gen = SshKeyGenerator(key)
        commands = gen.generate()

        assert len(commands) == 2
        assert (
            "set system login user vyos authentication public-keys "
            "admin@example.com key 'AAAAC3NzaC1lZDI1NTE5AAAAI...'"
        ) in commands[0]
        assert (
            "set system login user vyos authentication public-keys "
            "admin@example.com type ssh-ed25519"
        ) in commands[1]

    def test_generate_without_comment(self):
        """Test SSH key generation without comment (uses 'key1' as default)."""
        key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."
        gen = SshKeyGenerator(key)
        commands = gen.generate()

        assert len(commands) == 2
        assert (
            "set system login user vyos authentication public-keys "
            "key1 key 'AAAAB3NzaC1yc2EAAAADAQABAAABAQC...'"
        ) in commands[0]
        assert (
            "set system login user vyos authentication public-keys key1 type ssh-rsa"
        ) in commands[1]

    def test_generate_with_spaces_in_comment(self):
        """Test SSH key generation with spaces in comment (replaces with underscores)."""
        key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... John Doe"
        gen = SshKeyGenerator(key)
        commands = gen.generate()

        assert len(commands) == 2
        assert "John_Doe" in commands[0]
        assert "John_Doe" in commands[1]

    def test_generate_with_none(self):
        """Test SSH key generation with None."""
        gen = SshKeyGenerator(None)
        commands = gen.generate()

        assert len(commands) == 0

    def test_generate_with_invalid_key(self):
        """Test SSH key generation with invalid key format (too few parts)."""
        key = "invalid-key"
        gen = SshKeyGenerator(key)
        commands = gen.generate()

        assert len(commands) == 0


class TestInterfaceGenerator:
    """Tests for interface configuration generator."""

    def test_generate_single_interface(self):
        """Test interface generation with single interface."""
        iface = InterfaceConfig(
            name="eth0",
            ip=IPv4Address("10.0.1.1"),
            mask="255.255.255.0",
        )
        gen = InterfaceGenerator([iface], [])
        commands = gen.generate()

        assert len(commands) == 1
        assert "set interfaces ethernet eth0 address '10.0.1.1/24'" in commands

    def test_generate_multiple_interfaces(self):
        """Test interface generation with multiple interfaces."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.1.1"),
                mask="255.255.255.0",
            ),
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.255.0",
            ),
        ]
        gen = InterfaceGenerator(interfaces, [])
        commands = gen.generate()

        assert len(commands) == 2
        assert "set interfaces ethernet eth0 address '10.0.1.1/24'" in commands
        assert "set interfaces ethernet eth1 address '192.168.1.1/24'" in commands

    def test_generate_with_mtu(self):
        """Test interface generation with MTU specified."""
        iface = InterfaceConfig(
            name="eth0",
            ip=IPv4Address("10.0.1.1"),
            mask="255.255.255.0",
            mtu=9000,
        )
        gen = InterfaceGenerator([iface], [])
        commands = gen.generate()

        assert len(commands) == 2
        assert "set interfaces ethernet eth0 address '10.0.1.1/24'" in commands
        assert "set interfaces ethernet eth0 mtu 9000" in commands

    def test_generate_with_alias(self):
        """Test interface generation with alias (secondary IP)."""
        iface = InterfaceConfig(
            name="eth0",
            ip=IPv4Address("10.0.1.1"),
            mask="255.255.255.0",
        )
        alias = AliasConfig(
            interface="eth0",
            ip=IPv4Address("10.0.1.2"),
            mask="255.255.255.0",
        )
        gen = InterfaceGenerator([iface], [alias])
        commands = gen.generate()

        assert len(commands) == 2
        assert "set interfaces ethernet eth0 address '10.0.1.1/24'" in commands
        assert "set interfaces ethernet eth0 address '10.0.1.2/24'" in commands

    def test_generate_with_alias_no_mask(self):
        """Test interface generation with alias missing mask (uses parent mask)."""
        iface = InterfaceConfig(
            name="eth0",
            ip=IPv4Address("129.244.246.64"),
            mask="255.255.255.0",
        )
        alias = AliasConfig(
            interface="eth0",
            ip=IPv4Address("129.244.246.66"),
            mask=None,  # Missing mask (OpenNebula bug)
        )
        gen = InterfaceGenerator([iface], [alias])
        commands = gen.generate()

        assert len(commands) == 2
        assert "set interfaces ethernet eth0 address '129.244.246.64/24'" in commands
        assert "set interfaces ethernet eth0 address '129.244.246.66/24'" in commands

    def test_generate_with_multiple_aliases(self):
        """Test interface generation with multiple aliases on same interface."""
        iface = InterfaceConfig(
            name="eth0",
            ip=IPv4Address("10.0.1.1"),
            mask="255.255.255.0",
        )
        aliases = [
            AliasConfig(
                interface="eth0",
                ip=IPv4Address("10.0.1.2"),
                mask="255.255.255.0",
            ),
            AliasConfig(
                interface="eth0",
                ip=IPv4Address("10.0.1.3"),
                mask="255.255.255.0",
            ),
        ]
        gen = InterfaceGenerator([iface], aliases)
        commands = gen.generate()

        assert len(commands) == 3
        assert "set interfaces ethernet eth0 address '10.0.1.1/24'" in commands
        assert "set interfaces ethernet eth0 address '10.0.1.2/24'" in commands
        assert "set interfaces ethernet eth0 address '10.0.1.3/24'" in commands

    def test_generate_different_subnet_masks(self):
        """Test interface generation with different subnet masks."""
        interfaces = [
            InterfaceConfig(
                name="eth0",
                ip=IPv4Address("10.0.1.1"),
                mask="255.255.255.0",  # /24
            ),
            InterfaceConfig(
                name="eth1",
                ip=IPv4Address("192.168.1.1"),
                mask="255.255.0.0",  # /16
            ),
        ]
        gen = InterfaceGenerator(interfaces, [])
        commands = gen.generate()

        assert len(commands) == 2
        assert "set interfaces ethernet eth0 address '10.0.1.1/24'" in commands
        assert "set interfaces ethernet eth1 address '192.168.1.1/16'" in commands

    def test_generate_empty_config(self):
        """Test interface generation with no interfaces."""
        gen = InterfaceGenerator([], [])
        commands = gen.generate()

        assert len(commands) == 0


class TestGenerateConfig:
    """Tests for top-level generate_config function."""

    def test_generate_minimal_config(self):
        """Test config generation with minimal configuration."""
        config = RouterConfig(
            hostname="router-01",
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                )
            ],
        )
        commands = generate_config(config)

        # Should have hostname + interface
        assert len(commands) == 2
        assert "set system host-name 'router-01'" in commands
        assert "set interfaces ethernet eth0 address '10.0.1.1/24'" in commands

    def test_generate_full_system_config(self):
        """Test config generation with all system features."""
        config = RouterConfig(
            hostname="router-01",
            ssh_public_key="ssh-rsa AAAAB3NzaC1yc2E... user@host",
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                    mtu=9000,
                ),
                InterfaceConfig(
                    name="eth1",
                    ip=IPv4Address("192.168.1.1"),
                    mask="255.255.255.0",
                ),
            ],
            aliases=[
                AliasConfig(
                    interface="eth0",
                    ip=IPv4Address("10.0.1.2"),
                    mask="255.255.255.0",
                )
            ],
        )
        commands = generate_config(config)

        # Should have: hostname + 2 SSH key commands
        # + 3 interface commands (2 primary + 1 MTU) + 1 alias
        assert len(commands) == 7
        assert "set system host-name 'router-01'" in commands
        assert any("public-keys" in cmd for cmd in commands)
        assert "set interfaces ethernet eth0 address '10.0.1.1/24'" in commands
        assert "set interfaces ethernet eth0 mtu 9000" in commands
        assert "set interfaces ethernet eth1 address '192.168.1.1/24'" in commands
        assert "set interfaces ethernet eth0 address '10.0.1.2/24'" in commands

    def test_generate_no_optional_config(self):
        """Test config generation with no optional features."""
        config = RouterConfig(
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                )
            ]
        )
        commands = generate_config(config)

        # Should only have interface command
        assert len(commands) == 1
        assert "set interfaces ethernet eth0 address '10.0.1.1/24'" in commands

    def test_command_order(self):
        """Test that commands are generated in correct order (system, then interfaces)."""
        config = RouterConfig(
            hostname="router-01",
            ssh_public_key="ssh-rsa AAAAB3NzaC1yc2E... user@host",
            interfaces=[
                InterfaceConfig(
                    name="eth0",
                    ip=IPv4Address("10.0.1.1"),
                    mask="255.255.255.0",
                )
            ],
        )
        commands = generate_config(config)

        # Find indices of different command types
        hostname_idx = next(i for i, cmd in enumerate(commands) if "host-name" in cmd)
        ssh_key_idx = next(i for i, cmd in enumerate(commands) if "public-keys" in cmd)
        interface_idx = next(i for i, cmd in enumerate(commands) if "interfaces ethernet" in cmd)

        # System commands should come before interface commands
        assert hostname_idx < interface_idx
        assert ssh_key_idx < interface_idx
