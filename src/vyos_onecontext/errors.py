"""Error collection and reporting for vyos-onecontext.

This module provides utilities for collecting errors during contextualization
and reporting them at the end of the process. This allows us to apply all
valid configuration sections even when some sections have errors.
"""

import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Severity levels for errors."""

    WARNING = "warning"  # Non-critical error, doesn't affect exit code
    ERROR = "error"  # Critical error, affects exit code


@dataclass
class ContextError:
    """Represents an error encountered during contextualization.

    Attributes:
        section: The configuration section where the error occurred (e.g., "ROUTES_JSON")
        message: Human-readable error message
        exception: The original exception that caused the error (if any)
        severity: Error severity level
    """

    section: str
    message: str
    exception: Exception | None = None
    severity: ErrorSeverity = ErrorSeverity.ERROR

    def __str__(self) -> str:
        """Format error for logging."""
        if self.exception:
            return f"[{self.section}] {self.message}: {self.exception}"
        return f"[{self.section}] {self.message}"


class ErrorCollector:
    """Collects errors during contextualization for batch reporting.

    This class allows the contextualization process to continue even when
    individual sections fail, collecting all errors for reporting at the end.
    """

    def __init__(self) -> None:
        """Initialize an empty error collector."""
        self.errors: list[ContextError] = []

    def add_error(
        self,
        section: str,
        message: str,
        exception: Exception | None = None,
        severity: ErrorSeverity = ErrorSeverity.ERROR,
    ) -> None:
        """Add an error to the collection.

        Args:
            section: Configuration section where error occurred
            message: Human-readable error message
            exception: Original exception that caused the error
            severity: Error severity level
        """
        error = ContextError(
            section=section,
            message=message,
            exception=exception,
            severity=severity,
        )
        self.errors.append(error)

        # Log immediately at appropriate level
        if severity == ErrorSeverity.WARNING:
            logger.warning("%s", error)
        else:
            logger.error("%s", error)

    def has_errors(self) -> bool:
        """Check if any errors have been collected.

        Returns:
            True if any ERROR-level errors exist (warnings don't count)
        """
        return any(e.severity == ErrorSeverity.ERROR for e in self.errors)

    def has_warnings(self) -> bool:
        """Check if any warnings have been collected.

        Returns:
            True if any WARNING-level errors exist
        """
        return any(e.severity == ErrorSeverity.WARNING for e in self.errors)

    def get_error_count(self) -> int:
        """Get count of ERROR-level errors.

        Returns:
            Number of errors (not including warnings)
        """
        return sum(1 for e in self.errors if e.severity == ErrorSeverity.ERROR)

    def get_warning_count(self) -> int:
        """Get count of WARNING-level errors.

        Returns:
            Number of warnings
        """
        return sum(1 for e in self.errors if e.severity == ErrorSeverity.WARNING)

    def log_summary(self) -> None:
        """Log a summary of all collected errors.

        This should be called at the end of contextualization to provide
        a comprehensive error report.
        """
        if not self.errors:
            logger.info("Contextualization completed with no errors")
            return

        error_count = self.get_error_count()
        warning_count = self.get_warning_count()

        logger.error("=" * 80)
        logger.error("CONTEXTUALIZATION ERROR SUMMARY")
        logger.error("=" * 80)

        if error_count > 0:
            logger.error("Total errors: %d", error_count)
        if warning_count > 0:
            logger.warning("Total warnings: %d", warning_count)

        # Group errors by section
        errors_by_section: dict[str, list[ContextError]] = {}
        for error in self.errors:
            if error.section not in errors_by_section:
                errors_by_section[error.section] = []
            errors_by_section[error.section].append(error)

        # Log errors grouped by section
        for section, section_errors in sorted(errors_by_section.items()):
            logger.error("")
            logger.error("Section: %s (%d issues)", section, len(section_errors))
            for error in section_errors:
                level_str = error.severity.value.upper()
                if error.exception:
                    logger.error("  [%s] %s: %s", level_str, error.message, error.exception)
                else:
                    logger.error("  [%s] %s", level_str, error.message)

        logger.error("=" * 80)

        if error_count > 0:
            logger.error(
                "Contextualization completed with %d error(s) and %d warning(s)",
                error_count,
                warning_count,
            )
            logger.error(
                "Some configuration sections were skipped. Valid sections have been applied."
            )
        else:
            logger.warning(
                "Contextualization completed with %d warning(s)",
                warning_count,
            )
