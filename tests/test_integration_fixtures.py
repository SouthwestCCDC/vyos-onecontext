"""Tests for integration test fixtures.

These tests validate that the integration test context fixtures:
1. Can be parsed by the ContextParser
2. Produce valid RouterConfig models
3. Contain realistic, usable configurations

This allows testing the fixtures without requiring KVM/QEMU.
"""

import subprocess
import tempfile
from pathlib import Path

import pytest

from vyos_onecontext.parser import ContextParser

# Path to integration test fixtures
FIXTURES_DIR = Path(__file__).parent / "integration" / "contexts"


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

        This is a regression test for issue #40 where SSH keys with
        quoted comments caused parsing failures.
        """
        parser = ContextParser(str(FIXTURES_DIR / "quotes.env"))
        config = parser.parse()

        assert config.hostname == "test-quotes"
        assert config.ssh_public_key is not None
        # The key should contain the quoted comment
        assert '"admin@test"' in config.ssh_public_key
        assert len(config.interfaces) == 1

    def test_multi_interface_fixture_parses(self) -> None:
        """Test multi-interface.env fixture parses to valid RouterConfig."""
        parser = ContextParser(str(FIXTURES_DIR / "multi-interface.env"))
        config = parser.parse()

        assert config.hostname == "test-multi"
        assert len(config.interfaces) >= 2

        # Verify we have distinct interfaces
        interface_names = [iface.name for iface in config.interfaces]
        assert "eth0" in interface_names
        assert "eth1" in interface_names

    def test_all_fixtures_produce_valid_configs(self) -> None:
        """Test that all .env fixtures in the contexts directory parse successfully."""
        fixture_files = list(FIXTURES_DIR.glob("*.env"))
        assert len(fixture_files) >= 3, "Expected at least 3 fixture files"

        for fixture_path in fixture_files:
            parser = ContextParser(str(fixture_path))
            config = parser.parse()

            # Basic validation - should have at least one interface
            assert len(config.interfaces) >= 1, f"{fixture_path.name} should define at least one interface"

            # Hostname should be set
            assert config.hostname is not None, f"{fixture_path.name} should define a hostname"


class TestIsoCreationScript:
    """Test the create-test-iso.sh script."""

    @pytest.fixture
    def script_path(self) -> Path:
        """Return path to the ISO creation script."""
        return Path(__file__).parent / "integration" / "create-test-iso.sh"

    def test_script_exists_and_executable(self, script_path: Path) -> None:
        """Test that the script exists."""
        assert script_path.exists(), "create-test-iso.sh should exist"

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
        subprocess.run(["which", "genisoimage"], capture_output=True).returncode != 0
        and subprocess.run(["which", "mkisofs"], capture_output=True).returncode != 0,
        reason="Neither genisoimage nor mkisofs available",
    )
    def test_script_creates_iso(self, script_path: Path) -> None:
        """Test that the script creates a valid ISO file."""
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
