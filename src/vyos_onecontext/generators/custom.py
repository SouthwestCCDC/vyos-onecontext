"""Custom configuration generators (START_CONFIG, START_SCRIPT)."""

from vyos_onecontext.generators.base import BaseGenerator


class StartConfigGenerator(BaseGenerator):
    """Generate VyOS commands from START_CONFIG escape hatch.

    START_CONFIG allows operators to inject raw VyOS commands that will be
    executed after all generated configuration, but before commit.

    Commands are executed within the same configuration transaction as the
    generated config. No validation is performed on command syntax - operators
    are trusted to provide valid commands.
    """

    def __init__(self, start_config: str | None):
        """Initialize START_CONFIG generator.

        Args:
            start_config: Newline-separated VyOS commands, or None to skip
        """
        self.start_config = start_config

    def generate(self) -> list[str]:
        """Generate START_CONFIG commands.

        Splits the START_CONFIG string on newlines and filters out empty lines
        and comments.

        Returns:
            List of VyOS commands (typically 'set' commands) to execute
        """
        if self.start_config is None:
            return []

        commands: list[str] = []
        for line in self.start_config.splitlines():
            # Strip whitespace
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            commands.append(line)

        return commands
