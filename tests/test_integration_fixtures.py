"""Tests for integration test fixtures.

These tests validate that the integration test context fixtures:
1. Can be parsed by the ContextParser
2. Produce valid RouterConfig models
3. Contain realistic, usable configurations

This allows testing the fixtures without requiring KVM/QEMU.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from vyos_onecontext.errors import ErrorCollector
from vyos_onecontext.generators import generate_config
from vyos_onecontext.parser import ContextParser

# Path to integration test fixtures
FIXTURES_DIR = Path(__file__).parent / "integration" / "contexts"


class TestErrorScenarioFixtures:
    """Test error scenario fixtures behave as expected."""

    def test_invalid_json_fixture(self) -> None:
        """Test invalid-json.env fixture produces expected errors."""
        error_collector = ErrorCollector()
        parser = ContextParser(
            str(FIXTURES_DIR / "invalid-json.env"), error_collector=error_collector
        )
        config = parser.parse()

        # Valid sections should parse
        assert config.hostname == "test-invalid-json"
        assert len(config.interfaces) >= 1
        assert config.dhcp is not None

        # Invalid ROUTES_JSON should be None
        assert config.routes is None

        # Should have exactly one error for ROUTES_JSON
        assert error_collector.has_errors()
        assert error_collector.get_error_count() == 1
        assert error_collector.errors[0].section == "ROUTES_JSON"
        assert "Invalid JSON" in error_collector.errors[0].message

    def test_missing_required_fields_fixture(self) -> None:
        """Test missing-required-fields.env fixture produces expected errors."""
        error_collector = ErrorCollector()
        parser = ContextParser(
            str(FIXTURES_DIR / "missing-required-fields.env"),
            error_collector=error_collector,
        )
        config = parser.parse()

        # Valid sections should parse
        assert config.hostname == "test-missing-fields"
        assert len(config.interfaces) >= 1
        assert config.dhcp is not None

        # Invalid OSPF_JSON should be None (missing required 'enabled' field)
        assert config.ospf is None

        # Should have exactly one error for OSPF_JSON
        assert error_collector.has_errors()
        assert error_collector.get_error_count() == 1
        assert error_collector.errors[0].section == "OSPF_JSON"
        assert "Validation error" in error_collector.errors[0].message

    def test_partial_valid_fixture(self) -> None:
        """Test partial-valid.env fixture produces multiple expected errors."""
        error_collector = ErrorCollector()
        parser = ContextParser(
            str(FIXTURES_DIR / "partial-valid.env"), error_collector=error_collector
        )
        config = parser.parse()

        # Valid sections should parse
        assert config.hostname == "test-partial-valid"
        assert len(config.interfaces) >= 1
        assert config.dhcp is not None

        # Both ROUTES_JSON and OSPF_JSON should be None (both invalid)
        assert config.routes is None
        assert config.ospf is None

        # Should have exactly two errors
        assert error_collector.has_errors()
        assert error_collector.get_error_count() == 2

        # Verify both errors are present
        error_sections = [e.section for e in error_collector.errors]
        assert "ROUTES_JSON" in error_sections
        assert "OSPF_JSON" in error_sections

        # Verify error types
        routes_error = next(e for e in error_collector.errors if e.section == "ROUTES_JSON")
        ospf_error = next(e for e in error_collector.errors if e.section == "OSPF_JSON")

        assert "Invalid JSON" in routes_error.message
        assert "Validation error" in ospf_error.message


class TestFixturesParsing:
    """Test that all fixtures parse correctly through ContextParser."""

    def test_simple_fixture_parses(self) -> None:
        """Test simple.env fixture parses to valid RouterConfig."""
        parser = ContextParser(str(FIXTURES_DIR / "simple.env"))
        config = parser.parse()

        assert config.hostname == "test-simple"
        assert len(config.interfaces) == 1
        assert config.interfaces[0].name == "eth0"
        assert str(config.interfaces[0].ip) == "192.168.122.10"
        assert str(config.interfaces[0].gateway) == "192.168.122.1"

    def test_quotes_fixture_parses(self) -> None:
        """Test quotes.env fixture parses correctly.

        This was originally a regression test for issue #40 where SSH keys with
        quoted comments caused parsing failures. Now it validates basic parsing
        of the fixture without SSH keys.
        """
        parser = ContextParser(str(FIXTURES_DIR / "quotes.env"))
        config = parser.parse()

        assert config.hostname == "test-quotes"
        assert len(config.interfaces) == 1

    def test_multi_interface_fixture_parses(self) -> None:
        """Test multi-interface.env fixture parses to valid RouterConfig.

        This fixture uses aliases (secondary IPs) on eth0 since the QEMU
        test VM only has one network interface.
        """
        parser = ContextParser(str(FIXTURES_DIR / "multi-interface.env"))
        config = parser.parse()

        assert config.hostname == "test-multi"
        assert len(config.interfaces) >= 1
        assert len(config.aliases) >= 1  # Has at least one alias IP

        # Verify we have eth0 with aliases
        interface_names = [iface.name for iface in config.interfaces]
        assert "eth0" in interface_names

        # Check aliases are on eth0
        alias_interfaces = {alias.interface for alias in config.aliases}
        assert "eth0" in alias_interfaces

    def test_start_script_fixture_parses(self) -> None:
        """Test start-script.env fixture parses with START_SCRIPT content."""
        parser = ContextParser(str(FIXTURES_DIR / "start-script.env"))
        config = parser.parse()

        assert config.hostname == "test-start-script"
        assert config.start_script is not None
        assert "START_SCRIPT executed" in config.start_script
        assert config.start_script.startswith("#!/bin/bash")

    def test_vxlan_arcade_fixture_parses(self) -> None:
        """Test vxlan-arcade.env fixture parses with VXLAN_JSON content."""
        parser = ContextParser(str(FIXTURES_DIR / "vxlan-arcade.env"))
        config = parser.parse()

        assert config.hostname == "test-vxlan-arcade"
        assert len(config.interfaces) == 4  # eth0, eth1, eth2, eth3

        # VXLAN config should be present
        assert config.vxlan is not None
        assert len(config.vxlan.tunnels) == 2
        assert len(config.vxlan.bridges) == 1

        # Verify tunnel details
        tunnel_names = {t.name for t in config.vxlan.tunnels}
        assert tunnel_names == {"vxlan0", "vxlan1"}

        vxlan0 = next(t for t in config.vxlan.tunnels if t.name == "vxlan0")
        assert vxlan0.vni == 100
        assert str(vxlan0.remote) == "100.65.1.37"
        assert str(vxlan0.source_address) == "100.65.1.36"

        vxlan1 = next(t for t in config.vxlan.tunnels if t.name == "vxlan1")
        assert vxlan1.vni == 101
        assert str(vxlan1.remote) == "100.65.1.115"
        assert str(vxlan1.source_address) == "100.65.1.36"

        # Verify bridge details
        bridge = config.vxlan.bridges[0]
        assert bridge.name == "br0"
        assert bridge.address == "172.22.1.1/16"
        assert set(bridge.members) == {"eth2", "vxlan0", "vxlan1"}

        # Verify routes are present alongside VXLAN
        assert config.routes is not None
        assert len(config.routes.static) == 1

    def test_all_fixtures_produce_valid_configs(self) -> None:
        """Test that all .env fixtures in the contexts directory parse successfully.

        Error scenario fixtures (invalid-json, missing-required-fields, partial-valid)
        are explicitly skipped as they are designed to test error handling.
        """
        # Error scenario fixtures that should NOT parse successfully
        error_fixtures = {
            "invalid-json.env",
            "missing-required-fields.env",
            "partial-valid.env",
        }

        fixture_files = list(FIXTURES_DIR.glob("*.env"))
        assert len(fixture_files) >= 3, "Expected at least 3 fixture files"

        for fixture_path in fixture_files:
            # Skip error scenario fixtures
            if fixture_path.name in error_fixtures:
                continue

            parser = ContextParser(str(fixture_path))
            config = parser.parse()

            # Basic validation - should have at least one interface
            assert len(config.interfaces) >= 1, (
                f"{fixture_path.name} should define at least one interface"
            )

            # Hostname should be set
            assert config.hostname is not None, f"{fixture_path.name} should define a hostname"


class TestVxlanFunctionalValidation:
    """Functional tests for VXLAN configuration generation.

    These tests validate the complete pipeline from fixture file through
    ContextParser to command generation, verifying that:
    1. VXLAN tunnels are created with correct parameters
    2. Bridges are created with correct members
    3. Bridge gets the IP address (not the physical interface)
    4. Bridged interfaces do NOT receive IP addresses
    5. Non-bridged interfaces still receive IP addresses normally
    6. Command ordering is correct (interfaces → VXLAN → bridges)
    """

    def test_vxlan_arcade_commands_generation(self) -> None:
        """Test complete command generation for VXLAN arcade fixture."""
        parser = ContextParser(str(FIXTURES_DIR / "vxlan-arcade.env"))
        config = parser.parse()
        commands = generate_config(config)

        # Convert to set for easier searching
        commands_set = set(commands)

        # 1. VXLAN tunnel creation
        assert "set interfaces vxlan vxlan0 vni 100" in commands_set
        assert "set interfaces vxlan vxlan0 remote 100.65.1.37" in commands_set
        assert "set interfaces vxlan vxlan0 source-address 100.65.1.36" in commands_set
        assert (
            "set interfaces vxlan vxlan0 description 'Tunnel to Store 37'" in commands_set
        )

        assert "set interfaces vxlan vxlan1 vni 101" in commands_set
        assert "set interfaces vxlan vxlan1 remote 100.65.1.115" in commands_set
        assert "set interfaces vxlan vxlan1 source-address 100.65.1.36" in commands_set
        assert (
            "set interfaces vxlan vxlan1 description 'Tunnel to Store 114'" in commands_set
        )

        # 2. Bridge creation with members
        assert "set interfaces bridge br0 member interface eth2" in commands_set
        assert "set interfaces bridge br0 member interface vxlan0" in commands_set
        assert "set interfaces bridge br0 member interface vxlan1" in commands_set
        assert "set interfaces bridge br0 description 'Arcade network'" in commands_set

        # 3. Bridge gets the IP address
        assert "set interfaces bridge br0 address 172.22.1.1/16" in commands_set

        # 4. eth2 (bridged interface) should NOT get an IP address
        # Check that NO command assigns an IP to eth2
        eth2_ip_commands = [cmd for cmd in commands if "ethernet eth2 address" in cmd]
        assert len(eth2_ip_commands) == 0, (
            f"eth2 should not receive IP address (bridged interface), "
            f"but found: {eth2_ip_commands}"
        )

        # 5. Non-bridged interfaces should still get IPs normally
        assert "set interfaces ethernet eth0 address 10.2.6.36/24" in commands_set
        assert "set interfaces ethernet eth1 address 10.129.17.1/30" in commands_set
        assert "set interfaces ethernet eth3 address 192.168.1.1/24" in commands_set

        # 6. Management VRF on eth0
        assert "set interfaces ethernet eth0 vrf management" in commands_set

        # 7. Static routes coexist with VXLAN
        assert (
            "set protocols static route 100.65.1.0/24 next-hop 10.129.17.2"
            in commands_set
        )

    def test_vxlan_command_ordering(self) -> None:
        """Test that VXLAN commands appear in correct order.

        VyOS requires:
        1. Physical interfaces configured first (with VRF, before IPs)
        2. Interface IP addresses assigned
        3. VXLAN tunnels created (reference source IPs)
        4. Bridges created (reference VXLAN and physical interfaces)
        """
        parser = ContextParser(str(FIXTURES_DIR / "vxlan-arcade.env"))
        config = parser.parse()
        commands = generate_config(config)

        # Find indices of key command types
        vrf_indices = [
            i for i, cmd in enumerate(commands) if "ethernet eth0 vrf" in cmd
        ]
        interface_ip_indices = [
            i for i, cmd in enumerate(commands) if "ethernet eth" in cmd and "address" in cmd
        ]
        vxlan_indices = [
            i for i, cmd in enumerate(commands) if "vxlan vxlan" in cmd
        ]
        bridge_indices = [
            i for i, cmd in enumerate(commands) if "bridge br" in cmd
        ]

        # VRF assignment must come before interface IPs
        if vrf_indices and interface_ip_indices:
            assert min(vrf_indices) < min(interface_ip_indices), (
                "VRF assignment must come before interface IP configuration"
            )

        # Interface IPs must come before VXLAN tunnels
        if interface_ip_indices and vxlan_indices:
            assert max(interface_ip_indices) < min(vxlan_indices), (
                "Interface IP addresses must be configured before VXLAN tunnels"
            )

        # VXLAN tunnels must come before bridges
        if vxlan_indices and bridge_indices:
            assert max(vxlan_indices) < min(bridge_indices), (
                "VXLAN tunnels must be created before bridges"
            )

    def test_vxlan_with_no_ip_conflicts(self) -> None:
        """Test that bridged interfaces do not have conflicting IP assignments.

        When an interface is a bridge member, it should NOT receive an IP address
        via the normal interface generator. The bridge itself gets the IP.
        """
        parser = ContextParser(str(FIXTURES_DIR / "vxlan-arcade.env"))
        config = parser.parse()
        commands = generate_config(config)

        # eth2 is a bridge member in this fixture
        # It should not have any IP address commands
        eth2_commands = [cmd for cmd in commands if "ethernet eth2" in cmd]

        # eth2 should not appear in any IP address assignment
        for cmd in eth2_commands:
            assert "address" not in cmd, (
                f"eth2 is bridged and should not have IP address, "
                f"but found command: {cmd}"
            )

        # Bridge br0 should have the IP address instead
        bridge_ip_commands = [
            cmd for cmd in commands if "bridge br0 address" in cmd
        ]
        assert len(bridge_ip_commands) == 1
        assert "172.22.1.1/16" in bridge_ip_commands[0]


class TestIsoCreationScript:
    """Test the create-test-iso.sh script."""

    @pytest.fixture
    def script_path(self) -> Path:
        """Return path to the ISO creation script."""
        return Path(__file__).parent / "integration" / "create-test-iso.sh"

    def test_script_exists_and_executable(self, script_path: Path) -> None:
        """Test that the script exists and is executable."""
        assert script_path.exists(), "create-test-iso.sh should exist"
        assert os.access(script_path, os.X_OK), "create-test-iso.sh should be executable"

    def test_script_syntax_valid(self, script_path: Path) -> None:
        """Test that the script has valid bash syntax."""
        result = subprocess.run(
            ["bash", "-n", str(script_path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Syntax error in script: {result.stderr}"

    def test_script_has_usage_in_header(self, script_path: Path) -> None:
        """Test that the script documents its usage in the header."""
        content = script_path.read_text()
        assert "Usage:" in content, "Script should document usage in header comments"

    @pytest.mark.skipif(
        shutil.which("genisoimage") is None
        and shutil.which("mkisofs") is None
        and shutil.which("xorriso") is None,
        reason="No ISO creation tool available (genisoimage, mkisofs, or xorriso)",
    )
    def test_script_creates_iso(self, script_path: Path) -> None:
        """Test that the script creates a valid ISO file with correct contents."""
        with tempfile.TemporaryDirectory() as tmpdir:
            iso_path = Path(tmpdir) / "test.iso"
            context_path = FIXTURES_DIR / "simple.env"

            result = subprocess.run(
                ["bash", str(script_path), str(iso_path), str(context_path)],
                capture_output=True,
                text=True,
            )

            assert result.returncode == 0, f"ISO creation failed: {result.stderr}"
            assert iso_path.exists(), "ISO file should be created"
            assert iso_path.stat().st_size > 0, "ISO file should not be empty"

            # Verify ISO contains the context file with correct content
            extract_dir = Path(tmpdir) / "extracted"
            extract_dir.mkdir()

            if shutil.which("xorriso"):
                # Use xorriso to extract ISO contents
                extract_result = subprocess.run(
                    [
                        "xorriso",
                        "-osirrox",
                        "on",
                        "-indev",
                        str(iso_path),
                        "-extract",
                        "/",
                        str(extract_dir),
                    ],
                    capture_output=True,
                    text=True,
                )
                assert extract_result.returncode == 0, (
                    f"ISO extraction failed: {extract_result.stderr}"
                )

                # Verify context.sh exists and contains expected content
                context_in_iso = extract_dir / "context.sh"
                assert context_in_iso.exists(), "ISO should contain context.sh"

                expected_content = context_path.read_text()
                actual_content = context_in_iso.read_text()
                assert expected_content == actual_content, (
                    "context.sh in ISO should match input fixture"
                )
