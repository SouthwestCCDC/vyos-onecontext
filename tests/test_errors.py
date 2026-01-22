"""Tests for error collection and reporting."""

import logging

import pytest

from vyos_onecontext.errors import ContextError, ErrorCollector, ErrorSeverity


class TestContextError:
    """Tests for ContextError dataclass."""

    def test_error_string_without_exception(self) -> None:
        """Test string representation without exception."""
        error = ContextError(
            section="TEST_SECTION",
            message="Test error message",
        )
        assert str(error) == "[TEST_SECTION] Test error message"

    def test_error_string_with_exception(self) -> None:
        """Test string representation with exception."""
        exc = ValueError("invalid value")
        error = ContextError(
            section="TEST_SECTION",
            message="Test error message",
            exception=exc,
        )
        assert str(error) == "[TEST_SECTION] Test error message: invalid value"

    def test_default_severity(self) -> None:
        """Test default severity is ERROR."""
        error = ContextError(
            section="TEST_SECTION",
            message="Test error message",
        )
        assert error.severity == ErrorSeverity.ERROR


class TestErrorCollector:
    """Tests for ErrorCollector."""

    def test_empty_collector(self) -> None:
        """Test empty collector has no errors."""
        collector = ErrorCollector()
        assert not collector.has_errors()
        assert not collector.has_warnings()
        assert collector.get_error_count() == 0
        assert collector.get_warning_count() == 0

    def test_add_error(self) -> None:
        """Test adding an error."""
        collector = ErrorCollector()
        collector.add_error(
            section="TEST_SECTION",
            message="Test error",
        )
        assert collector.has_errors()
        assert collector.get_error_count() == 1
        assert len(collector.errors) == 1
        assert collector.errors[0].section == "TEST_SECTION"
        assert collector.errors[0].message == "Test error"

    def test_add_warning(self) -> None:
        """Test adding a warning."""
        collector = ErrorCollector()
        collector.add_error(
            section="TEST_SECTION",
            message="Test warning",
            severity=ErrorSeverity.WARNING,
        )
        assert not collector.has_errors()  # Warnings don't count as errors
        assert collector.has_warnings()
        assert collector.get_error_count() == 0
        assert collector.get_warning_count() == 1

    def test_add_multiple_errors(self) -> None:
        """Test adding multiple errors."""
        collector = ErrorCollector()
        collector.add_error(section="SECTION1", message="Error 1")
        collector.add_error(section="SECTION2", message="Error 2")
        collector.add_error(
            section="SECTION3",
            message="Warning 1",
            severity=ErrorSeverity.WARNING,
        )
        assert collector.get_error_count() == 2
        assert collector.get_warning_count() == 1
        assert len(collector.errors) == 3

    def test_add_error_with_exception(self) -> None:
        """Test adding error with exception."""
        collector = ErrorCollector()
        exc = ValueError("test exception")
        collector.add_error(
            section="TEST_SECTION",
            message="Test error",
            exception=exc,
        )
        assert collector.errors[0].exception == exc

    def test_log_summary_empty(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test log summary with no errors."""
        collector = ErrorCollector()
        with caplog.at_level(logging.INFO):
            collector.log_summary()
        assert "completed with no errors" in caplog.text

    def test_log_summary_with_errors(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test log summary with errors."""
        collector = ErrorCollector()
        collector.add_error(section="ROUTES_JSON", message="Invalid route")
        collector.add_error(section="OSPF_JSON", message="Invalid OSPF config")

        with caplog.at_level(logging.ERROR):
            collector.log_summary()

        # Check summary contains key elements
        assert "ERROR SUMMARY" in caplog.text
        assert "Total errors: 2" in caplog.text
        assert "ROUTES_JSON" in caplog.text
        assert "OSPF_JSON" in caplog.text
        assert "Invalid route" in caplog.text
        assert "Invalid OSPF config" in caplog.text

    def test_log_summary_with_warnings(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test log summary with warnings."""
        collector = ErrorCollector()
        collector.add_error(
            section="TEST_SECTION",
            message="Test warning",
            severity=ErrorSeverity.WARNING,
        )

        with caplog.at_level(logging.WARNING):
            collector.log_summary()

        assert "Total warnings: 1" in caplog.text

    def test_log_summary_groups_by_section(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test log summary groups errors by section."""
        collector = ErrorCollector()
        collector.add_error(section="ROUTES_JSON", message="Error 1")
        collector.add_error(section="ROUTES_JSON", message="Error 2")
        collector.add_error(section="OSPF_JSON", message="Error 3")

        with caplog.at_level(logging.ERROR):
            collector.log_summary()

        # Should show section grouping
        assert "Section: ROUTES_JSON (2 issues)" in caplog.text
        assert "Section: OSPF_JSON (1 issues)" in caplog.text

    def test_errors_logged_immediately(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that errors are logged immediately when added."""
        collector = ErrorCollector()

        with caplog.at_level(logging.ERROR):
            collector.add_error(section="TEST", message="Immediate error")

        assert "Immediate error" in caplog.text
        assert "[TEST]" in caplog.text

    def test_warnings_logged_at_warning_level(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that warnings are logged at WARNING level."""
        collector = ErrorCollector()

        with caplog.at_level(logging.WARNING):
            collector.add_error(
                section="TEST",
                message="Immediate warning",
                severity=ErrorSeverity.WARNING,
            )

        # Should be in warning logs
        assert any(
            record.levelname == "WARNING" and "Immediate warning" in record.message
            for record in caplog.records
        )
