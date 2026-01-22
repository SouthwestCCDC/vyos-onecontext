"""Entry point for VyOS contextualization.

This module is invoked by the boot script to apply OpenNebula context
to the VyOS router configuration.

Usage:
    python -m vyos_onecontext [context_file]

Arguments:
    context_file: Path to the OpenNebula context file (default: /var/run/one-context/one_env)
"""

import argparse
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from vyos_onecontext.generators import generate_config
from vyos_onecontext.models import OnecontextMode
from vyos_onecontext.parser import parse_context
from vyos_onecontext.wrapper import VyOSConfigError, VyOSConfigSession

logger = logging.getLogger(__name__)

# Path where we create a marker to disable future onecontext runs (freeze mode)
FREEZE_MARKER_PATH = "/config/.onecontext-frozen"

# Exit codes
EXIT_SUCCESS = 0
EXIT_NO_CONTEXT = 0  # Not an error - fresh boot without context
EXIT_PARSE_ERROR = 1
EXIT_CONFIG_ERROR = 2
EXIT_FROZEN = 0  # Not an error - intentionally frozen


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the application.

    Args:
        verbose: If True, use DEBUG level. Otherwise, use INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def is_frozen() -> bool:
    """Check if onecontext has been frozen (disabled for future boots).

    Returns:
        True if the freeze marker exists, indicating onecontext should not run.
    """
    return Path(FREEZE_MARKER_PATH).exists()


def create_freeze_marker() -> None:
    """Create the freeze marker file to disable future onecontext runs."""
    Path(FREEZE_MARKER_PATH).touch()
    logger.info("Created freeze marker at %s", FREEZE_MARKER_PATH)


def run_start_script(script_content: str, timeout: int = 300) -> None:
    """Execute the START_SCRIPT after configuration is committed.

    Supports both inline scripts and file paths. If script_content looks like
    a file path (starts with / and exists), it's executed directly. Otherwise,
    it's treated as inline script content and written to a temporary file.

    Security note: START_SCRIPT content comes from OpenNebula context, which is
    infrastructure-controlled and implicitly trusted. No path restrictions are
    applied - the script can execute from any location with full privileges.

    Args:
        script_content: Shell script content or path to script file.
        timeout: Maximum execution time in seconds (default: 300 = 5 minutes).
    """
    logger.info("Executing START_SCRIPT")

    # Initialize variables to avoid UnboundLocalError in finally block
    script_path = ""
    cleanup_script = False

    # Check if script_content is a file path (strip whitespace first)
    script_content_stripped = script_content.strip()
    is_file_path = (
        script_content_stripped.startswith("/") and Path(script_content_stripped).exists()
    )

    if is_file_path:
        # Execute the script file directly
        script_path = script_content_stripped
        cleanup_script = False
        logger.debug("START_SCRIPT: executing file at %s", script_path)
    else:
        # Write inline script to temporary file
        logger.debug("START_SCRIPT: writing inline script to temporary file")
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".sh",
            delete=False,
        ) as script_file:
            script_path = script_file.name
            cleanup_script = True
            script_file.write(script_content)

    # Ensure script is executable for inline (temporary) scripts only
    if cleanup_script:
        try:
            os.chmod(script_path, 0o700)
        except OSError as e:
            logger.warning(
                "Failed to set executable permissions on temporary START_SCRIPT %s: %s",
                script_path,
                e,
            )

    try:
        # Execute with timeout
        result = subprocess.run(
            ["/bin/bash", script_path],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )

        if result.returncode != 0:
            logger.error(
                "START_SCRIPT failed with exit code %d: %s",
                result.returncode,
                result.stderr or result.stdout,
            )
        else:
            logger.info("START_SCRIPT completed successfully")
            if result.stdout:
                logger.debug("START_SCRIPT output: %s", result.stdout)

    except subprocess.TimeoutExpired:
        logger.error(
            "START_SCRIPT exceeded timeout of %d seconds and was terminated",
            timeout,
        )
    # Catch all exceptions to ensure START_SCRIPT failures don't abort boot.
    # This is intentional: START_SCRIPT is a non-critical post-configuration hook,
    # and any failure should be logged but not prevent the system from starting.
    # Note: This does not catch SystemExit or KeyboardInterrupt (BaseException subclasses).
    except Exception as e:
        logger.error("START_SCRIPT execution failed: %s", e)
    finally:
        # Clean up the temporary script if we created one
        if cleanup_script:
            Path(script_path).unlink(missing_ok=True)


def apply_configuration(
    context_path: str,
    wrapper_path: str | None = None,
    dry_run: bool = False,
) -> int:
    """Parse context and apply configuration to VyOS.

    Args:
        context_path: Path to the OpenNebula context file.
        wrapper_path: Path to vyatta-cfg-cmd-wrapper (for testing).
        dry_run: If True, generate commands but don't execute them.

    Returns:
        Exit code (0 for success, non-zero for errors).
    """
    # Check if frozen
    if is_frozen():
        logger.info(
            "Onecontext is frozen (marker exists at %s). Skipping configuration.",
            FREEZE_MARKER_PATH,
        )
        return EXIT_FROZEN

    # Check if context file exists
    if not Path(context_path).exists():
        logger.info(
            "Context file not found at %s. This is normal on fresh boot without "
            "OpenNebula context.",
            context_path,
        )
        return EXIT_NO_CONTEXT

    # Parse context
    try:
        logger.info("Parsing context from %s", context_path)
        config = parse_context(context_path)
    except FileNotFoundError:
        logger.info("Context file not found. Skipping configuration.")
        return EXIT_NO_CONTEXT
    except ValueError as e:
        logger.error("Failed to parse context: %s", e)
        return EXIT_PARSE_ERROR

    # Generate commands
    logger.info("Generating VyOS configuration commands")
    commands = generate_config(config)

    if not commands:
        logger.info("No configuration commands to apply")
        return EXIT_SUCCESS

    logger.info("Generated %d configuration commands", len(commands))
    for cmd in commands:
        logger.info("VYOS_CMD: %s", cmd)

    # In dry-run mode, just print commands and exit
    if dry_run:
        print("Dry run - commands that would be executed:")
        for cmd in commands:
            print(f"  {cmd}")
        return EXIT_SUCCESS

    # Apply configuration
    try:
        session = VyOSConfigSession(wrapper_path=wrapper_path)

        # Verify we have the right group membership
        if not session.verify_group():
            logger.warning(
                "Not running with vyattacfg group. Configuration may fail. "
                "Use 'sg vyattacfg' to run with correct group."
            )

        with session:
            session.run_commands(commands)

    except VyOSConfigError as e:
        logger.error("Configuration failed: %s", e)
        return EXIT_CONFIG_ERROR

    # Handle post-commit actions based on mode
    mode = config.onecontext_mode

    if mode == OnecontextMode.STATELESS:
        logger.info("Configuration applied (stateless mode - not saved)")

    elif mode == OnecontextMode.SAVE:
        logger.warning(
            "Configuration applied and saved (WARNING: will regenerate from "
            "non-fresh state on next boot)"
        )
        try:
            session.save()
        except VyOSConfigError as e:
            logger.error("Failed to save configuration: %s", e)
            return EXIT_CONFIG_ERROR

    elif mode == OnecontextMode.FREEZE:
        logger.info(
            "Configuration applied, saved, and frozen (onecontext disabled for future boots)"
        )
        try:
            session.save()
            create_freeze_marker()
        except VyOSConfigError as e:
            logger.error("Failed to save configuration: %s", e)
            return EXIT_CONFIG_ERROR

    # Run START_SCRIPT if present
    if config.start_script:
        run_start_script(config.start_script)

    return EXIT_SUCCESS


def main() -> int:
    """Main entry point for VyOS contextualization.

    Returns:
        Exit code.
    """
    parser = argparse.ArgumentParser(
        description="Apply OpenNebula context to VyOS configuration",
        prog="python -m vyos_onecontext",
    )
    parser.add_argument(
        "context_file",
        nargs="?",
        default="/var/run/one-context/one_env",
        help="Path to the OpenNebula context file (default: /var/run/one-context/one_env)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose (debug) logging",
    )
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Generate commands but don't execute them",
    )
    parser.add_argument(
        "--wrapper-path",
        default=None,
        help="Path to vyatta-cfg-cmd-wrapper (for testing)",
    )

    args = parser.parse_args()

    setup_logging(verbose=args.verbose)

    logger.info("Starting VyOS contextualization")

    return apply_configuration(
        context_path=args.context_file,
        wrapper_path=args.wrapper_path,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    sys.exit(main())
