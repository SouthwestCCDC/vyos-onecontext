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
        assert len(config.aliases) >= 2  # Has aliases for secondary IPs

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
