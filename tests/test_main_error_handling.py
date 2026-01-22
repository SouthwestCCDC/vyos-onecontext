"""Tests for main module error handling."""

import logging
from pathlib import Path

import pytest

from vyos_onecontext.__main__ import EXIT_PARSE_ERROR, EXIT_SUCCESS, apply_configuration


class TestApplyConfigurationErrorHandling:
    """Tests for apply_configuration error handling."""

    def test_apply_with_partial_valid_config(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that valid sections are applied even when some sections fail."""
        context_file = tmp_path / "one_env"
        content = """
HOSTNAME="test-router"
ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ROUTES_JSON="invalid json here"
OSPF_JSON="also invalid"
"""
        context_file.write_text(content)

        with caplog.at_level(logging.INFO):
            exit_code = apply_configuration(
                context_path=str(context_file),
                dry_run=True,  # Don't try to actually configure VyOS
            )

        # Should return error code due to parse errors
        assert exit_code == EXIT_PARSE_ERROR

        # But should still generate commands for valid sections
        assert "Generated" in caplog.text
        assert "configuration commands" in caplog.text

        # Should have hostname and interface commands
        assert "set system host-name test-router" in caplog.text
        assert "set interfaces ethernet eth0 address 10.0.1.1/24" in caplog.text

        # Error summary should be logged
        assert "ERROR SUMMARY" in caplog.text
        assert "ROUTES_JSON" in caplog.text
        assert "OSPF_JSON" in caplog.text

    def test_apply_with_all_valid_config(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that valid config completes successfully."""
        context_file = tmp_path / "one_env"
        content = """
HOSTNAME="test-router"
ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
"""
        context_file.write_text(content)

        with caplog.at_level(logging.INFO):
            exit_code = apply_configuration(
                context_path=str(context_file),
                dry_run=True,
            )

        # Should succeed
        assert exit_code == EXIT_SUCCESS

        # Should generate commands
        assert "Generated" in caplog.text

        # No error summary
        assert "ERROR SUMMARY" not in caplog.text

    def test_apply_with_all_json_sections_invalid(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test behavior when all JSON sections are invalid but base config is valid."""
        context_file = tmp_path / "one_env"
        content = """
HOSTNAME="test-router"
ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ROUTES_JSON="invalid"
OSPF_JSON="invalid"
DHCP_JSON="invalid"
NAT_JSON="invalid"
FIREWALL_JSON="invalid"
"""
        context_file.write_text(content)

        with caplog.at_level(logging.INFO):
            exit_code = apply_configuration(
                context_path=str(context_file),
                dry_run=True,
            )

        # Should return error code
        assert exit_code == EXIT_PARSE_ERROR

        # But should still generate basic commands (hostname, interface)
        assert "Generated" in caplog.text

        # Error summary should show all sections
        assert "ERROR SUMMARY" in caplog.text
        assert "Total errors: 5" in caplog.text

    def test_apply_shows_error_details(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that error summary shows detailed information."""
        context_file = tmp_path / "one_env"
        content = """
ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ROUTES_JSON="{invalid json"
"""
        context_file.write_text(content)

        with caplog.at_level(logging.ERROR):
            exit_code = apply_configuration(
                context_path=str(context_file),
                dry_run=True,
            )

        assert exit_code == EXIT_PARSE_ERROR

        # Error details should be in summary
        assert "ERROR SUMMARY" in caplog.text
        assert "ROUTES_JSON" in caplog.text
        assert "Invalid JSON" in caplog.text

    def test_apply_with_no_commands_but_errors(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test behavior when errors prevent command generation."""
        context_file = tmp_path / "one_env"
        # Only invalid sections, no valid base config
        content = """
ROUTES_JSON="invalid"
"""
        context_file.write_text(content)

        with caplog.at_level(logging.INFO):
            exit_code = apply_configuration(
                context_path=str(context_file),
                dry_run=True,
            )

        # Should return error code
        assert exit_code == EXIT_PARSE_ERROR

        # Should note no commands to apply
        assert "No configuration commands to apply" in caplog.text

        # Error summary should still be shown
        assert "ERROR SUMMARY" in caplog.text

    def test_error_summary_groups_errors_by_section(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that error summary groups errors by section."""
        context_file = tmp_path / "one_env"
        content = """
ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ROUTES_JSON="invalid1"
OSPF_JSON="invalid2"
"""
        context_file.write_text(content)

        with caplog.at_level(logging.ERROR):
            exit_code = apply_configuration(
                context_path=str(context_file),
                dry_run=True,
            )

        assert exit_code == EXIT_PARSE_ERROR

        # Should show section grouping in summary
        log_text = caplog.text
        routes_idx = log_text.find("Section: ROUTES_JSON")
        ospf_idx = log_text.find("Section: OSPF_JSON")

        # Both sections should be present
        assert routes_idx != -1
        assert ospf_idx != -1

    def test_warning_message_about_partial_application(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that warning message is shown about partial application."""
        context_file = tmp_path / "one_env"
        content = """
HOSTNAME="test-router"
ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ROUTES_JSON="invalid"
"""
        context_file.write_text(content)

        with caplog.at_level(logging.INFO):
            exit_code = apply_configuration(
                context_path=str(context_file),
                dry_run=True,
            )

        assert exit_code == EXIT_PARSE_ERROR

        # Should have error summary messages
        assert "Contextualization completed with 1 error(s)" in caplog.text
        assert "Some configuration sections were skipped" in caplog.text
        assert "Valid sections have been applied" in caplog.text
