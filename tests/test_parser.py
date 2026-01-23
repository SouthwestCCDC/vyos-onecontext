"""Tests for context file parser."""

import json
from pathlib import Path

import pytest

from vyos_onecontext.models import OnecontextMode
from vyos_onecontext.parser import ContextParser, parse_context


class TestShellVariableParsing:
    """Tests for shell variable parsing."""

    def test_simple_variable(self, tmp_path: Path) -> None:
        """Test parsing simple quoted variable."""
        context_file = tmp_path / "one_env"
        context_file.write_text('HOSTNAME="router-01"\n')

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert parser.variables["HOSTNAME"] == "router-01"

    def test_unquoted_variable(self, tmp_path: Path) -> None:
        """Test parsing unquoted variable."""
        context_file = tmp_path / "one_env"
        context_file.write_text("ETH0_MTU=1500\n")

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert parser.variables["ETH0_MTU"] == "1500"

    def test_multiline_variable(self, tmp_path: Path) -> None:
        """Test parsing multiline variable."""
        context_file = tmp_path / "one_env"
        content = """SSH_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABtest
line2
line3"
"""
        context_file.write_text(content)

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert "SSH_PUBLIC_KEY" in parser.variables
        assert "line2" in parser.variables["SSH_PUBLIC_KEY"]
        assert "line3" in parser.variables["SSH_PUBLIC_KEY"]

    def test_empty_variable(self, tmp_path: Path) -> None:
        """Test parsing empty variable."""
        context_file = tmp_path / "one_env"
        context_file.write_text('ETH0_ALIAS0_MASK=""\n')

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert parser.variables["ETH0_ALIAS0_MASK"] == ""

    def test_comment_lines(self, tmp_path: Path) -> None:
        """Test that comment lines are skipped."""
        context_file = tmp_path / "one_env"
        content = """# This is a comment
HOSTNAME="router-01"
# Another comment
ETH0_IP="10.0.1.1"
"""
        context_file.write_text(content)

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert "HOSTNAME" in parser.variables
        assert "ETH0_IP" in parser.variables
        assert len(parser.variables) == 2

    def test_mixed_quotes(self, tmp_path: Path) -> None:
        """Test parsing variables with different quote styles."""
        context_file = tmp_path / "one_env"
        content = """VAR1="double"
VAR2='single'
"""
        context_file.write_text(content)

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert parser.variables["VAR1"] == "double"
        assert parser.variables["VAR2"] == "single"

    def test_escaped_quotes_double(self, tmp_path: Path) -> None:
        """Test parsing double-quoted value with escaped quotes."""
        context_file = tmp_path / "one_env"
        context_file.write_text('TEST="value with \\"quote\\""\n')

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert parser.variables["TEST"] == 'value with "quote"'

    def test_escaped_quotes_single(self, tmp_path: Path) -> None:
        """Test parsing single-quoted value with escaped quotes."""
        context_file = tmp_path / "one_env"
        context_file.write_text("TEST='value with \\'quote\\''\n")

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert parser.variables["TEST"] == "value with 'quote'"

    def test_escaped_backslash(self, tmp_path: Path) -> None:
        """Test parsing value with escaped backslash."""
        context_file = tmp_path / "one_env"
        context_file.write_text('TEST="path\\\\to\\\\file"\n')

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert parser.variables["TEST"] == "path\\to\\file"

    def test_mixed_escapes(self, tmp_path: Path) -> None:
        """Test parsing value with mixed escape sequences."""
        context_file = tmp_path / "one_env"
        context_file.write_text('TEST="He said \\"Hello\\\\\\" to me"\n')

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert parser.variables["TEST"] == 'He said "Hello\\" to me'

    def test_whitespace_only_unquoted(self, tmp_path: Path) -> None:
        """Test parsing unquoted value that is whitespace-only."""
        context_file = tmp_path / "one_env"
        context_file.write_text("TEST=   \n")

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert parser.variables["TEST"] == ""

    def test_empty_unquoted(self, tmp_path: Path) -> None:
        """Test parsing unquoted value that is empty."""
        context_file = tmp_path / "one_env"
        context_file.write_text("TEST=\n")

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert parser.variables["TEST"] == ""

    def test_trailing_backslash_bounds_check(self, tmp_path: Path) -> None:
        """Test _find_closing_quote handles text ending with backslash."""
        context_file = tmp_path / "one_env"
        # Test case where the search string ends with a lone backslash
        # This directly tests the bounds check fix in _find_closing_quote
        # The value 'test\' (backslash at very end) followed by closing quote
        context_file.write_text('TEST="test\\\\"\n')  # test\\ in file = test\ as value

        parser = ContextParser(str(context_file))
        parser._read_variables()

        # Should parse successfully - value is 'test\' (single backslash)
        assert "TEST" in parser.variables
        assert parser.variables["TEST"] == "test\\"


class TestInterfaceParsing:
    """Tests for interface parsing."""

    def test_single_interface(self, tmp_path: Path) -> None:
        """Test parsing single interface."""
        context_file = tmp_path / "one_env"
        content = """ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ETH0_GATEWAY="10.0.1.254"
ETH0_DNS="8.8.8.8"
ETH0_MTU="1500"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert len(config.interfaces) == 1
        iface = config.interfaces[0]
        assert iface.name == "eth0"
        assert str(iface.ip) == "10.0.1.1"
        assert iface.mask == "255.255.255.0"
        assert str(iface.gateway) == "10.0.1.254"
        assert str(iface.dns) == "8.8.8.8"
        assert iface.mtu == 1500
        assert iface.management is False

    def test_management_interface(self, tmp_path: Path) -> None:
        """Test parsing interface with management flag."""
        context_file = tmp_path / "one_env"
        content = """ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ETH0_VROUTER_MANAGEMENT="YES"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert len(config.interfaces) == 1
        assert config.interfaces[0].management is True

    def test_multiple_interfaces(self, tmp_path: Path) -> None:
        """Test parsing multiple interfaces."""
        context_file = tmp_path / "one_env"
        content = """ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ETH1_IP="192.168.1.1"
ETH1_MASK="255.255.255.0"
ETH2_IP="172.16.0.1"
ETH2_MASK="255.255.0.0"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert len(config.interfaces) == 3
        assert config.interfaces[0].name == "eth0"
        assert config.interfaces[1].name == "eth1"
        assert config.interfaces[2].name == "eth2"

    def test_interface_without_mask_raises_error(self, tmp_path: Path) -> None:
        """Test that interface without mask raises error."""
        context_file = tmp_path / "one_env"
        content = """ETH0_IP="10.0.1.1"
"""
        context_file.write_text(content)

        with pytest.raises(ValueError, match="has IP but no MASK"):
            parse_context(str(context_file))


class TestAliasParsing:
    """Tests for alias parsing."""

    def test_single_alias(self, tmp_path: Path) -> None:
        """Test parsing single alias."""
        context_file = tmp_path / "one_env"
        content = """ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ETH0_ALIAS0_IP="10.0.1.2"
ETH0_ALIAS0_MASK="255.255.255.0"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert len(config.aliases) == 1
        alias = config.aliases[0]
        assert alias.interface == "eth0"
        assert str(alias.ip) == "10.0.1.2"
        assert alias.mask == "255.255.255.0"

    def test_alias_with_empty_mask(self, tmp_path: Path) -> None:
        """Test parsing alias with empty mask (OpenNebula bug)."""
        context_file = tmp_path / "one_env"
        content = """ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ETH0_ALIAS0_IP="10.0.1.2"
ETH0_ALIAS0_MASK=""
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert len(config.aliases) == 1
        alias = config.aliases[0]
        assert alias.interface == "eth0"
        assert str(alias.ip) == "10.0.1.2"
        assert alias.mask is None

    def test_multiple_aliases_on_same_interface(self, tmp_path: Path) -> None:
        """Test parsing multiple aliases on same interface."""
        context_file = tmp_path / "one_env"
        content = """ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ETH0_ALIAS0_IP="10.0.1.2"
ETH0_ALIAS0_MASK="255.255.255.0"
ETH0_ALIAS1_IP="10.0.1.3"
ETH0_ALIAS1_MASK="255.255.255.0"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert len(config.aliases) == 2
        assert config.aliases[0].interface == "eth0"
        assert config.aliases[1].interface == "eth0"
        assert str(config.aliases[0].ip) == "10.0.1.2"
        assert str(config.aliases[1].ip) == "10.0.1.3"

    def test_aliases_on_multiple_interfaces(self, tmp_path: Path) -> None:
        """Test parsing aliases on different interfaces."""
        context_file = tmp_path / "one_env"
        content = """ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ETH0_ALIAS0_IP="10.0.1.2"
ETH0_ALIAS0_MASK="255.255.255.0"
ETH1_IP="192.168.1.1"
ETH1_MASK="255.255.255.0"
ETH1_ALIAS0_IP="192.168.1.2"
ETH1_ALIAS0_MASK="255.255.255.0"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert len(config.aliases) == 2
        assert config.aliases[0].interface == "eth0"
        assert config.aliases[1].interface == "eth1"


class TestOperationalVariables:
    """Tests for operational variable parsing."""

    def test_hostname(self, tmp_path: Path) -> None:
        """Test hostname parsing."""
        context_file = tmp_path / "one_env"
        context_file.write_text('HOSTNAME="router-01"\n')

        config = parse_context(str(context_file))

        assert config.hostname == "router-01"

    def test_ssh_public_key(self, tmp_path: Path) -> None:
        """Test SSH public key parsing."""
        context_file = tmp_path / "one_env"
        context_file.write_text('SSH_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+test"\n')

        config = parse_context(str(context_file))

        assert config.ssh_public_key == "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+test"

    def test_ssh_public_key_multiple_keys(self, tmp_path: Path) -> None:
        """Test SSH public key with multiple keys (newline separated)."""
        context_file = tmp_path / "one_env"
        # Multiple SSH keys on separate lines (literal newlines in the value)
        content = """SSH_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+key1 user1@host1
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+key2 user2@host2
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest3 user3@host3"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.ssh_public_key is not None
        # Should preserve literal newlines between keys
        assert "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+key1 user1@host1" in config.ssh_public_key
        assert "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+key2 user2@host2" in config.ssh_public_key
        assert "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest3 user3@host3" in config.ssh_public_key
        # Verify literal newlines are preserved
        assert "\n" in config.ssh_public_key

    def test_onecontext_mode_stateless(self, tmp_path: Path) -> None:
        """Test ONECONTEXT_MODE stateless."""
        context_file = tmp_path / "one_env"
        context_file.write_text('ONECONTEXT_MODE="stateless"\n')

        config = parse_context(str(context_file))

        assert config.onecontext_mode == OnecontextMode.STATELESS

    def test_onecontext_mode_freeze(self, tmp_path: Path) -> None:
        """Test ONECONTEXT_MODE freeze."""
        context_file = tmp_path / "one_env"
        context_file.write_text('ONECONTEXT_MODE="freeze"\n')

        config = parse_context(str(context_file))

        assert config.onecontext_mode == OnecontextMode.FREEZE

    def test_onecontext_mode_default(self, tmp_path: Path) -> None:
        """Test default ONECONTEXT_MODE when not specified."""
        context_file = tmp_path / "one_env"
        context_file.write_text("")

        config = parse_context(str(context_file))

        assert config.onecontext_mode == OnecontextMode.STATELESS

    def test_onecontext_mode_invalid(self, tmp_path: Path) -> None:
        """Test invalid ONECONTEXT_MODE defaults to stateless."""
        context_file = tmp_path / "one_env"
        context_file.write_text('ONECONTEXT_MODE="invalid"\n')

        config = parse_context(str(context_file))

        assert config.onecontext_mode == OnecontextMode.STATELESS


class TestJsonVariables:
    """Tests for JSON variable parsing."""

    def test_routes_json(self, tmp_path: Path) -> None:
        """Test ROUTES_JSON parsing."""
        context_file = tmp_path / "one_env"
        routes_data = {
            "static": [
                {
                    "interface": "eth1",
                    "destination": "0.0.0.0/0",
                    "gateway": "10.0.1.254",
                }
            ]
        }
        # Need interface to satisfy RouterConfig validation
        content = f"""ETH1_IP="10.0.1.1"
ETH1_MASK="255.255.255.0"
ROUTES_JSON='{json.dumps(routes_data)}'
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.routes is not None
        assert len(config.routes.static) == 1
        assert config.routes.static[0].interface == "eth1"
        assert config.routes.static[0].destination == "0.0.0.0/0"

    def test_ospf_json(self, tmp_path: Path) -> None:
        """Test OSPF_JSON parsing."""
        context_file = tmp_path / "one_env"
        ospf_data = {
            "enabled": True,
            "router_id": "10.0.0.1",
            "interfaces": [{"name": "eth1", "area": "0.0.0.0"}],
            "redistribute": ["connected"],
        }
        # Need interface to satisfy RouterConfig validation
        content = f"""ETH1_IP="10.0.1.1"
ETH1_MASK="255.255.255.0"
OSPF_JSON='{json.dumps(ospf_data)}'
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.ospf is not None
        assert config.ospf.enabled is True
        assert str(config.ospf.router_id) == "10.0.0.1"
        assert len(config.ospf.interfaces) == 1

    def test_dhcp_json(self, tmp_path: Path) -> None:
        """Test DHCP_JSON parsing."""
        context_file = tmp_path / "one_env"
        dhcp_data = {
            "pools": [
                {
                    "interface": "eth1",
                    "range_start": "10.1.1.100",
                    "range_end": "10.1.1.200",
                    "gateway": "10.1.1.1",
                    "dns": ["10.1.1.1"],
                }
            ]
        }
        # Need interface to satisfy RouterConfig validation
        content = f"""ETH1_IP="10.1.1.1"
ETH1_MASK="255.255.255.0"
DHCP_JSON='{json.dumps(dhcp_data)}'
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.dhcp is not None
        assert len(config.dhcp.pools) == 1
        assert config.dhcp.pools[0].interface == "eth1"

    def test_nat_json(self, tmp_path: Path) -> None:
        """Test NAT_JSON parsing."""
        context_file = tmp_path / "one_env"
        nat_data = {
            "source": [
                {
                    "outbound_interface": "eth0",
                    "source_address": "10.0.0.0/8",
                    "translation": "masquerade",
                }
            ]
        }
        # Need interface to satisfy RouterConfig validation
        content = f"""ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
NAT_JSON='{json.dumps(nat_data)}'
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.nat is not None
        assert len(config.nat.source) == 1
        assert config.nat.source[0].outbound_interface == "eth0"

    def test_firewall_json(self, tmp_path: Path) -> None:
        """Test FIREWALL_JSON parsing."""
        context_file = tmp_path / "one_env"
        firewall_data = {
            "groups": {
                "network": {"GAME": ["10.64.0.0/10"]},
                "address": {},
                "port": {},
            },
            "zones": {"WAN": {"name": "WAN", "interfaces": ["eth0"], "default_action": "drop"}},
            "policies": [],
        }
        # Need interface to satisfy RouterConfig validation
        content = f"""ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
FIREWALL_JSON='{json.dumps(firewall_data)}'
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.firewall is not None
        assert "GAME" in config.firewall.groups.network
        assert "WAN" in config.firewall.zones

    def test_malformed_json(self, tmp_path: Path) -> None:
        """Test that malformed JSON raises error."""
        context_file = tmp_path / "one_env"
        context_file.write_text("ROUTES_JSON='{\"invalid\": json}'\n")

        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_context(str(context_file))

    def test_invalid_json_schema(self, tmp_path: Path) -> None:
        """Test that JSON with invalid schema raises error."""
        context_file = tmp_path / "one_env"
        # Missing required fields
        context_file.write_text("OSPF_JSON='{\"interfaces\": []}'\n")

        with pytest.raises(ValueError, match="Validation error"):
            parse_context(str(context_file))

    def test_json_routes_parsing(self, tmp_path: Path) -> None:
        """Test JSON parsing with routes data.

        This verifies the parser correctly handles JSON route configuration.
        Uses json.dumps() which produces compact single-line JSON without
        newlines (unless indent parameter is specified).
        """
        context_file = tmp_path / "one_env"
        # JSON with route data - tests that JSON parsing works correctly
        routes_data = {
            "static": [
                {
                    "interface": "eth1",
                    "destination": "0.0.0.0/0",
                    "gateway": "10.0.1.254",
                }
            ]
        }
        content = f"""ETH1_IP="10.0.1.1"
ETH1_MASK="255.255.255.0"
ROUTES_JSON='{json.dumps(routes_data)}'
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.routes is not None
        assert len(config.routes.static) == 1
        route = config.routes.static[0]
        assert route.interface == "eth1"
        assert route.destination == "0.0.0.0/0"
        assert str(route.gateway) == "10.0.1.254"

    def test_json_nested_with_whitespace(self, tmp_path: Path) -> None:
        """Test JSON parsing with complex nested structures and whitespace."""
        context_file = tmp_path / "one_env"
        # Multi-line formatted JSON (note: JSON string itself spans lines in shell value)
        firewall_data = {
            "groups": {
                "network": {
                    "INTERNAL": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                    "DMZ": ["10.10.0.0/16"],
                },
                "address": {"DNS_SERVERS": ["8.8.8.8", "8.8.4.4", "1.1.1.1"]},
                "port": {"WEB_PORTS": ["80", "443"]},
            },
            "zones": {
                "LAN": {"name": "LAN", "interfaces": ["eth1"], "default_action": "drop"},
                "WAN": {"name": "WAN", "interfaces": ["eth0"], "default_action": "drop"},
            },
            "policies": [],
        }
        # Pretty-print JSON which includes newlines
        json_str = json.dumps(firewall_data, indent=2)
        # Put in context file with newlines preserved
        content = f"""ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ETH1_IP="10.0.2.1"
ETH1_MASK="255.255.255.0"
FIREWALL_JSON='{json_str}'
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.firewall is not None
        assert "INTERNAL" in config.firewall.groups.network
        assert "DMZ" in config.firewall.groups.network
        assert "DNS_SERVERS" in config.firewall.groups.address
        assert "LAN" in config.firewall.zones
        assert "WAN" in config.firewall.zones


class TestMultilineEdgeCases:
    """Tests for edge cases in multiline value parsing."""

    def test_literal_newlines_preserved(self, tmp_path: Path) -> None:
        """Test that literal newlines in multiline values are preserved."""
        context_file = tmp_path / "one_env"
        # Test that literal newlines in the file are preserved as-is
        content = """TEST_VAR="Line 1
Line 2
Line 3"
"""
        context_file.write_text(content)

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert "TEST_VAR" in parser.variables
        value = parser.variables["TEST_VAR"]
        # Should contain literal newlines
        assert value == "Line 1\nLine 2\nLine 3"

    def test_empty_lines_in_multiline_value(self, tmp_path: Path) -> None:
        """Test multiline values containing empty lines."""
        context_file = tmp_path / "one_env"
        content = """SCRIPT="#!/bin/bash

echo 'Starting'

echo 'Done'"
"""
        context_file.write_text(content)

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert "SCRIPT" in parser.variables
        value = parser.variables["SCRIPT"]
        # Should preserve empty lines
        assert value == "#!/bin/bash\n\necho 'Starting'\n\necho 'Done'"

    def test_multiline_with_trailing_spaces(self, tmp_path: Path) -> None:
        """Test that trailing spaces on lines are stripped in multiline values."""
        context_file = tmp_path / "one_env"
        # Note: spaces after "command1" before the newline
        content = 'CONFIG="command1   \ncommand2\ncommand3  "\n'
        context_file.write_text(content)

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert "CONFIG" in parser.variables
        value = parser.variables["CONFIG"]
        # First line is stripped via .strip() at line 118 in parser.py,
        # so trailing spaces after "command1" are removed.
        # Subsequent lines (command2, command3) are NOT stripped, preserving spaces.
        assert value == "command1\ncommand2\ncommand3  "

    def test_multiline_value_with_comment_char(self, tmp_path: Path) -> None:
        """Test multiline values containing # character (not treated as comment inside quotes)."""
        context_file = tmp_path / "one_env"
        content = """SCRIPT="#!/bin/bash
# This is a comment inside the script
echo 'test'"
"""
        context_file.write_text(content)

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert "SCRIPT" in parser.variables
        value = parser.variables["SCRIPT"]
        # # should be preserved as part of the value
        assert value == "#!/bin/bash\n# This is a comment inside the script\necho 'test'"

    def test_single_quote_multiline(self, tmp_path: Path) -> None:
        """Test multiline values with single quotes."""
        context_file = tmp_path / "one_env"
        content = """SCRIPT='#!/bin/bash
echo "test"
exit 0'
"""
        context_file.write_text(content)

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert "SCRIPT" in parser.variables
        value = parser.variables["SCRIPT"]
        # Single quotes should preserve everything literally, including double quotes
        assert value == '#!/bin/bash\necho "test"\nexit 0'

    def test_very_long_multiline_value(self, tmp_path: Path) -> None:
        """Test parsing of very long multiline values."""
        context_file = tmp_path / "one_env"
        # Create a long multi-line script
        lines = [f"echo 'Line {i}'" for i in range(100)]
        script_content = "\n".join(lines)
        content = f'LONG_SCRIPT="{script_content}"\n'
        context_file.write_text(content)

        parser = ContextParser(str(context_file))
        parser._read_variables()

        assert "LONG_SCRIPT" in parser.variables
        value = parser.variables["LONG_SCRIPT"]
        # Should contain all 100 lines
        assert value.count("\n") == 99
        assert "echo 'Line 0'" in value
        assert "echo 'Line 99'" in value


class TestEscapeHatches:
    """Tests for escape hatch variables."""

    def test_start_config(self, tmp_path: Path) -> None:
        """Test START_CONFIG parsing."""
        context_file = tmp_path / "one_env"
        content = """START_CONFIG="set system option performance throughput
set system syslog global facility all level info"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.start_config is not None
        assert "performance throughput" in config.start_config

    def test_start_config_multiline_commands(self, tmp_path: Path) -> None:
        """Test START_CONFIG with multiple VyOS commands across many lines."""
        context_file = tmp_path / "one_env"
        content = """START_CONFIG="set system option performance throughput
set system syslog global facility all level info
set system syslog global facility local7 level debug
set system console device ttyS0 speed 115200
set system time-zone UTC"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.start_config is not None
        # Verify all commands are preserved with literal newlines
        assert "performance throughput" in config.start_config
        assert "facility all level info" in config.start_config
        assert "facility local7 level debug" in config.start_config
        assert "ttyS0 speed 115200" in config.start_config
        assert "time-zone UTC" in config.start_config
        # Verify literal newlines preserved
        lines = config.start_config.split("\n")
        assert len(lines) == 5

    def test_start_script(self, tmp_path: Path) -> None:
        """Test START_SCRIPT parsing."""
        context_file = tmp_path / "one_env"
        content = """START_SCRIPT="#!/bin/bash
echo 'Configuration complete' >> /var/log/contextualization.log"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.start_script is not None
        assert "#!/bin/bash" in config.start_script

    def test_start_script_multiline_shell_script(self, tmp_path: Path) -> None:
        """Test START_SCRIPT with complete multiline shell script."""
        context_file = tmp_path / "one_env"
        content = """START_SCRIPT="#!/bin/bash
# Post-configuration script
set -e

LOG_FILE=/var/log/contextualization.log

echo 'Starting post-configuration tasks...' | tee -a $LOG_FILE

# Configure firewall rules
if [ -f /config/scripts/firewall.sh ]; then
    bash /config/scripts/firewall.sh >> $LOG_FILE 2>&1
fi

# Check connectivity
ping -c 3 8.8.8.8 >> $LOG_FILE 2>&1 || echo 'Warning: No internet connectivity' | tee -a $LOG_FILE

echo 'Post-configuration complete' | tee -a $LOG_FILE"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.start_script is not None
        # Verify key parts of the script
        assert "#!/bin/bash" in config.start_script
        assert "set -e" in config.start_script
        assert "LOG_FILE=/var/log/contextualization.log" in config.start_script
        assert "Starting post-configuration tasks..." in config.start_script
        assert "ping -c 3 8.8.8.8" in config.start_script
        # Verify literal newlines preserved
        lines = config.start_script.split("\n")
        assert len(lines) >= 10

    def test_start_script_with_quotes_and_special_chars(self, tmp_path: Path) -> None:
        """Test START_SCRIPT with embedded quotes and special characters."""
        context_file = tmp_path / "one_env"
        content = """START_SCRIPT="#!/bin/bash
echo 'Router configured at: $(date)'
echo \\"Status: OK\\"
logger -t onecontext 'Configuration applied successfully'"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.start_script is not None
        assert "#!/bin/bash" in config.start_script
        assert "$(date)" in config.start_script
        # Check that escaped quotes are processed correctly
        assert '"Status: OK"' in config.start_script
        assert "logger -t onecontext" in config.start_script

    def test_start_script_timeout_default(self, tmp_path: Path) -> None:
        """Test START_SCRIPT_TIMEOUT defaults to 300 seconds."""
        context_file = tmp_path / "one_env"
        content = """START_SCRIPT="#!/bin/bash
echo 'test'"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.start_script_timeout == 300

    def test_start_script_timeout_default_when_not_provided(self, tmp_path: Path) -> None:
        """Test START_SCRIPT_TIMEOUT defaults to 300 when variable is absent."""
        context_file = tmp_path / "one_env"
        # Empty context file - no START_SCRIPT_TIMEOUT variable
        context_file.write_text("")

        config = parse_context(str(context_file))

        assert config.start_script_timeout == 300

    def test_start_script_timeout_custom(self, tmp_path: Path) -> None:
        """Test START_SCRIPT_TIMEOUT with custom value."""
        context_file = tmp_path / "one_env"
        content = """START_SCRIPT="#!/bin/bash
echo 'test'"
START_SCRIPT_TIMEOUT="600"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.start_script_timeout == 600

    def test_start_script_timeout_minimum(self, tmp_path: Path) -> None:
        """Test START_SCRIPT_TIMEOUT minimum value."""
        context_file = tmp_path / "one_env"
        content = """START_SCRIPT_TIMEOUT="1"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.start_script_timeout == 1

    def test_start_script_timeout_maximum(self, tmp_path: Path) -> None:
        """Test START_SCRIPT_TIMEOUT maximum value."""
        context_file = tmp_path / "one_env"
        content = """START_SCRIPT_TIMEOUT="3600"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.start_script_timeout == 3600

    def test_start_script_timeout_too_small(self, tmp_path: Path) -> None:
        """Test START_SCRIPT_TIMEOUT rejects values below 1."""
        context_file = tmp_path / "one_env"
        content = """START_SCRIPT_TIMEOUT="0"
"""
        context_file.write_text(content)

        with pytest.raises(ValueError, match="START_SCRIPT_TIMEOUT must be at least 1 second"):
            parse_context(str(context_file))

    def test_start_script_timeout_too_large(self, tmp_path: Path) -> None:
        """Test START_SCRIPT_TIMEOUT rejects values above 3600."""
        context_file = tmp_path / "one_env"
        content = """START_SCRIPT_TIMEOUT="3601"
"""
        context_file.write_text(content)

        with pytest.raises(ValueError, match="START_SCRIPT_TIMEOUT cannot exceed 3600 seconds"):
            parse_context(str(context_file))

    def test_start_script_timeout_invalid_format(self, tmp_path: Path) -> None:
        """Test START_SCRIPT_TIMEOUT handles invalid format gracefully."""
        context_file = tmp_path / "one_env"
        content = """START_SCRIPT_TIMEOUT="not-a-number"
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        # Should fall back to default
        assert config.start_script_timeout == 300


class TestCompleteContextFile:
    """Tests for complete context files."""

    def test_minimal_config(self, tmp_path: Path) -> None:
        """Test minimal valid configuration."""
        context_file = tmp_path / "one_env"
        context_file.write_text("")

        config = parse_context(str(context_file))

        assert config.hostname is None
        assert config.onecontext_mode == OnecontextMode.STATELESS
        assert len(config.interfaces) == 0

    def test_comprehensive_config(self, tmp_path: Path) -> None:
        """Test comprehensive configuration with all features."""
        context_file = tmp_path / "one_env"
        content = """# Identity
HOSTNAME="router-01"
SSH_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+test"

# Operational
ONECONTEXT_MODE="stateless"

# Interfaces
ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ETH0_VROUTER_MANAGEMENT="YES"

ETH1_IP="192.168.1.1"
ETH1_MASK="255.255.255.0"
ETH1_GATEWAY="192.168.1.254"

# Aliases
ETH1_ALIAS0_IP="192.168.1.2"
ETH1_ALIAS0_MASK="255.255.255.0"

# Routes (line broken for readability)
ROUTES_JSON='{"static": [{"interface": "eth1", "destination": "0.0.0.0/0", \
"gateway": "192.168.1.254"}]}'

# OSPF (line broken for readability)
OSPF_JSON='{"enabled": true, "router_id": "10.0.0.1", \
"interfaces": [{"name": "eth1", "area": "0.0.0.0"}]}'

# DHCP (line broken for readability)
DHCP_JSON='{"pools": [{"interface": "eth1", "range_start": "192.168.1.100", \
"range_end": "192.168.1.200", "gateway": "192.168.1.1", "dns": ["192.168.1.1"]}]}'

# NAT (line broken for readability)
NAT_JSON='{"source": [{"outbound_interface": "eth1", "source_address": "10.0.0.0/8", \
"translation": "masquerade"}]}'

# Firewall (line broken for readability)
FIREWALL_JSON='{"groups": {"network": {}, "address": {}, "port": {}}, \
"zones": {"WAN": {"name": "WAN", "interfaces": ["eth1"], "default_action": "drop"}}, \
"policies": []}'
"""
        context_file.write_text(content)

        config = parse_context(str(context_file))

        assert config.hostname == "router-01"
        assert len(config.interfaces) == 2
        assert len(config.aliases) == 1
        assert config.routes is not None
        assert config.ospf is not None
        assert config.dhcp is not None
        assert config.nat is not None
        assert config.firewall is not None


class TestErrorCases:
    """Tests for error handling."""

    def test_missing_file(self) -> None:
        """Test that missing file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            parse_context("/nonexistent/path")

    def test_nat_invalid_interface_reference(self, tmp_path: Path) -> None:
        """Test that NAT rule with invalid interface reference fails validation."""
        context_file = tmp_path / "one_env"
        content = """ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"

NAT_JSON='{"source": [{"outbound_interface": "eth99", "translation": "masquerade"}]}'
"""
        context_file.write_text(content)

        with pytest.raises(ValueError, match="non-existent outbound_interface"):
            parse_context(str(context_file))


class TestParserAPI:
    """Tests for parser API."""

    def test_context_parser_class(self, tmp_path: Path) -> None:
        """Test using ContextParser class directly."""
        context_file = tmp_path / "one_env"
        context_file.write_text('HOSTNAME="test"\n')

        parser = ContextParser(str(context_file))
        config = parser.parse()

        assert config.hostname == "test"

    def test_parse_context_function(self, tmp_path: Path) -> None:
        """Test using parse_context convenience function."""
        context_file = tmp_path / "one_env"
        context_file.write_text('HOSTNAME="test"\n')

        config = parse_context(str(context_file))

        assert config.hostname == "test"
