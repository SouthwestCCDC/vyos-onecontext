"""Base generator class for VyOS command generation."""

from abc import ABC, abstractmethod


class BaseGenerator(ABC):
    """Base class for VyOS command generators.

    All generator classes should inherit from this base class and implement
    the generate() method to produce VyOS 'set' commands.
    """

    @abstractmethod
    def generate(self) -> list[str]:
        """Generate VyOS configuration commands.

        Returns:
            List of VyOS 'set' commands as strings
        """
        pass
