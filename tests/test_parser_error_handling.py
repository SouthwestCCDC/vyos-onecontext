"""Tests for parser error handling and collection."""

from pathlib import Path

import pytest

from vyos_onecontext.errors import ErrorCollector
from vyos_onecontext.parser import parse_context


class TestParserErrorCollection:
    """Tests for parser error collection behavior."""

    def test_parse_with_invalid_json_section(self, tmp_path: Path) -> None:
        """Test that invalid JSON sections are collected as errors."""
        context_file = tmp_path / "one_env"
        content = """
ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ROUTES_JSON="invalid json {["
"""
        context_file.write_text(content)

        error_collector = ErrorCollector()
        config = parse_context(str(context_file), error_collector=error_collector)

        # Should still parse successfully (with partial config)
        assert config.interfaces
        assert len(config.interfaces) == 1
        assert str(config.interfaces[0].ip) == "10.0.1.1"

        # But routes should be None due to parse error
        assert config.routes is None

        # Error should be collected
        assert error_collector.has_errors()
        assert error_collector.get_error_count() == 1
        assert error_collector.errors[0].section == "ROUTES_JSON"
        assert "Invalid JSON" in error_collector.errors[0].message

    def test_parse_with_multiple_invalid_sections(self, tmp_path: Path) -> None:
        """Test that multiple invalid sections are all collected."""
        context_file = tmp_path / "one_env"
        content = """
ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ROUTES_JSON="invalid json"
OSPF_JSON="also invalid"
DHCP_JSON="{"incomplete": true"
"""
        context_file.write_text(content)

        error_collector = ErrorCollector()
        config = parse_context(str(context_file), error_collector=error_collector)

        # Valid interface should still be parsed
        assert config.interfaces
        assert len(config.interfaces) == 1

        # Invalid sections should be None
        assert config.routes is None
        assert config.ospf is None
        assert config.dhcp is None

        # All errors should be collected
        assert error_collector.get_error_count() == 3
        sections = [e.section for e in error_collector.errors]
        assert "ROUTES_JSON" in sections
        assert "OSPF_JSON" in sections
        assert "DHCP_JSON" in sections

    def test_parse_with_validation_error(self, tmp_path: Path) -> None:
        """Test that validation errors are collected."""
        context_file = tmp_path / "one_env"
        # ROUTES_JSON with invalid structure (missing required field: interface or next_hop)
        # Use single quotes to avoid shell escaping issues
        content = """ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ROUTES_JSON='{"static": [{"destination": "192.168.1.0/24"}]}'
"""
        context_file.write_text(content)

        error_collector = ErrorCollector()
        config = parse_context(str(context_file), error_collector=error_collector)

        # Valid interface should still be parsed
        assert config.interfaces

        # Routes should be None due to validation error
        assert config.routes is None

        # Validation error should be collected
        assert error_collector.has_errors()
        assert any("Validation error" in e.message for e in error_collector.errors)

    def test_parse_without_error_collector_raises(self, tmp_path: Path) -> None:
        """Test that without error collector, parser raises exceptions."""
        context_file = tmp_path / "one_env"
        content = """
ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ROUTES_JSON="invalid json"
"""
        context_file.write_text(content)

        # Without error collector, should raise ValueError
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_context(str(context_file), error_collector=None)

    def test_parse_with_all_valid_sections(self, tmp_path: Path) -> None:
        """Test that valid config generates no errors."""
        context_file = tmp_path / "one_env"
        # Use single quotes to avoid shell escaping issues
        route_json = (
            '{"static": [{"interface": "eth0", '
            '"destination": "192.168.1.0/24", "gateway": "10.0.1.254"}]}'
        )
        content = f"""ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ROUTES_JSON='{route_json}'
"""
        context_file.write_text(content)

        error_collector = ErrorCollector()
        config = parse_context(str(context_file), error_collector=error_collector)

        # Should parse successfully
        assert config.interfaces
        assert config.routes
        assert len(config.routes.static) == 1

        # No errors should be collected
        assert not error_collector.has_errors()
        assert error_collector.get_error_count() == 0

    def test_parse_with_missing_optional_sections(self, tmp_path: Path) -> None:
        """Test that missing optional sections don't generate errors."""
        context_file = tmp_path / "one_env"
        content = """
ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
"""
        context_file.write_text(content)

        error_collector = ErrorCollector()
        config = parse_context(str(context_file), error_collector=error_collector)

        # Should parse successfully with only interface
        assert config.interfaces
        assert config.routes is None
        assert config.ospf is None

        # No errors (missing optional sections is not an error)
        assert not error_collector.has_errors()

    def test_parse_empty_json_variable(self, tmp_path: Path) -> None:
        """Test that empty JSON variables are handled gracefully."""
        context_file = tmp_path / "one_env"
        content = """
ETH0_IP="10.0.1.1"
ETH0_MASK="255.255.255.0"
ROUTES_JSON=""
"""
        context_file.write_text(content)

        error_collector = ErrorCollector()
        config = parse_context(str(context_file), error_collector=error_collector)

        # Empty string should be treated as "not present"
        assert config.routes is None
        assert not error_collector.has_errors()
