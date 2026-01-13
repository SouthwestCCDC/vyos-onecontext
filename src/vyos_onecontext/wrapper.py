"""VyOS configuration wrapper for vyatta-cfg-cmd-wrapper.

This module provides a Python interface for executing VyOS configuration commands
through the vyatta-cfg-cmd-wrapper. All configuration changes are made within a
session (begin -> commands -> commit -> end).

IMPORTANT: This wrapper MUST run with the 'vyattacfg' group, NOT with sudo.
Running with sudo will break manual VyOS configuration sessions.
"""

import grp
import logging
import os
import subprocess
from typing import Self

logger = logging.getLogger(__name__)


class VyOSConfigError(Exception):
    """Exception raised when VyOS configuration operations fail."""

    pass


class VyOSConfigSession:
    """Context manager for VyOS configuration sessions.

    Provides a safe way to make VyOS configuration changes by managing the
    session lifecycle (begin, commands, commit, end) and handling errors.

    The wrapper must run with the 'vyattacfg' group to access VyOS configuration.
    Using sudo will break manual configuration sessions.

    Example:
        with VyOSConfigSession() as session:
            session.set(["system", "host-name", "router01"])
            session.set(["interfaces", "ethernet", "eth0", "address", "10.0.1.1/24"])
            # commit happens automatically on exit

    Attributes:
        wrapper_path: Path to the vyatta-cfg-cmd-wrapper executable.
        _in_session: Whether we are currently in an active session.
    """

    DEFAULT_WRAPPER_PATH = "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper"

    def __init__(self, wrapper_path: str | None = None) -> None:
        """Initialize the VyOS configuration session.

        Args:
            wrapper_path: Path to vyatta-cfg-cmd-wrapper. If None, uses the default
                         path (/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper).
        """
        self.wrapper_path = wrapper_path or self.DEFAULT_WRAPPER_PATH
        self._in_session = False

    def __enter__(self) -> Self:
        """Enter the configuration session context.

        Returns:
            Self for use in with statement.

        Raises:
            VyOSConfigError: If session cannot be started.
        """
        self.begin()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit the configuration session context.

        If no exception occurred, commits changes before ending the session.
        Always ends the session, even if an error occurred.

        Args:
            exc_type: Exception type if an error occurred.
            exc_val: Exception value if an error occurred.
            exc_tb: Exception traceback if an error occurred.
        """
        try:
            if exc_type is None and self._in_session:
                # No exception, commit the changes
                self.commit()
        finally:
            if self._in_session:
                self.end()

    def verify_group(self) -> bool:
        """Verify that the current process has the vyattacfg group.

        Returns:
            True if the process has vyattacfg group access, False otherwise.
        """
        try:
            vyattacfg_gid = grp.getgrnam("vyattacfg").gr_gid
        except KeyError:
            logger.warning("vyattacfg group does not exist on this system")
            return False

        # Check if vyattacfg is in our supplementary groups or is our effective GID
        return vyattacfg_gid == os.getegid() or vyattacfg_gid in os.getgroups()

    def _run_wrapper(self, *args: str) -> subprocess.CompletedProcess[str]:
        """Run the vyatta-cfg-cmd-wrapper with the given arguments.

        Args:
            *args: Arguments to pass to the wrapper.

        Returns:
            CompletedProcess with stdout and stderr.

        Raises:
            VyOSConfigError: If the wrapper command fails.
        """
        cmd = [self.wrapper_path, *args]
        logger.debug("Running wrapper command: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            raise VyOSConfigError(
                f"VyOS wrapper not found at {self.wrapper_path}. "
                "Is this running on a VyOS system?"
            ) from None
        except OSError as e:
            raise VyOSConfigError(f"Failed to execute VyOS wrapper: {e}") from e

        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip() or "Unknown error"
            raise VyOSConfigError(
                f"VyOS wrapper command failed: {' '.join(args)}\n"
                f"Exit code: {result.returncode}\n"
                f"Error: {error_msg}"
            )

        return result

    def begin(self) -> None:
        """Begin a configuration session.

        Raises:
            VyOSConfigError: If session cannot be started.
        """
        if self._in_session:
            logger.warning("begin() called while already in session")
            return

        logger.info("Beginning VyOS configuration session")
        self._run_wrapper("begin")
        self._in_session = True

    def end(self) -> None:
        """End the configuration session.

        Raises:
            VyOSConfigError: If session cannot be ended.
        """
        if not self._in_session:
            logger.warning("end() called while not in session")
            return

        logger.info("Ending VyOS configuration session")
        try:
            self._run_wrapper("end")
        finally:
            self._in_session = False

    def set(self, path: list[str]) -> None:
        """Set a configuration value.

        Args:
            path: Configuration path components (e.g., ["system", "host-name", "router01"])

        Raises:
            VyOSConfigError: If the set command fails.
            ValueError: If path is empty.
        """
        if not path:
            raise ValueError("Configuration path cannot be empty")

        if not self._in_session:
            raise VyOSConfigError("Cannot set configuration outside of a session")

        logger.debug("Setting: %s", " ".join(path))
        self._run_wrapper("set", *path)

    def delete(self, path: list[str]) -> None:
        """Delete a configuration value.

        Args:
            path: Configuration path components to delete.

        Raises:
            VyOSConfigError: If the delete command fails.
            ValueError: If path is empty.
        """
        if not path:
            raise ValueError("Configuration path cannot be empty")

        if not self._in_session:
            raise VyOSConfigError("Cannot delete configuration outside of a session")

        logger.debug("Deleting: %s", " ".join(path))
        self._run_wrapper("delete", *path)

    def commit(self) -> None:
        """Commit the current configuration changes.

        This applies changes to the running configuration but does not save
        them to persistent storage.

        Raises:
            VyOSConfigError: If the commit fails.
        """
        if not self._in_session:
            raise VyOSConfigError("Cannot commit configuration outside of a session")

        logger.info("Committing VyOS configuration")
        self._run_wrapper("commit")

    def save(self) -> None:
        """Save the current configuration to persistent storage.

        Note: In stateless mode, this should NOT be called. The configuration
        should be regenerated from context on every boot.

        Raises:
            VyOSConfigError: If the save fails.
        """
        logger.info("Saving VyOS configuration to persistent storage")
        self._run_wrapper("save")

    def run_commands(self, commands: list[str]) -> None:
        """Run a list of VyOS set commands.

        Each command should be a full VyOS 'set' command string, e.g.,
        "set system host-name router01". The 'set' prefix is optional and
        will be added if missing.

        Args:
            commands: List of VyOS commands to execute.

        Raises:
            VyOSConfigError: If any command fails.
        """
        for cmd in commands:
            # Strip leading 'set ' if present, then split into path components
            if cmd.startswith("set "):
                cmd = cmd[4:]
            path = cmd.split()
            if path:
                self.set(path)
