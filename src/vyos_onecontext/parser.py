"""Context file parser for OpenNebula contextualization.

This module parses the OpenNebula context file (/var/run/one-context/one_env)
and converts shell variable assignments into validated Pydantic models.
"""

import json
import re
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from vyos_onecontext.errors import ErrorCollector, ErrorSeverity
from vyos_onecontext.models.config import OnecontextMode, RouterConfig
from vyos_onecontext.models.dhcp import DhcpConfig
from vyos_onecontext.models.firewall import FirewallConfig
from vyos_onecontext.models.interface import AliasConfig, InterfaceConfig
from vyos_onecontext.models.nat import NatConfig
from vyos_onecontext.models.routing import OspfConfig, RoutesConfig

T = TypeVar("T", bound=BaseModel)


class ContextParser:
    """Parser for OpenNebula context files.

    Reads shell variable assignments from the context file and converts them
    into structured configuration objects.
    """

    def __init__(
        self,
        path: str = "/var/run/one-context/one_env",
        error_collector: ErrorCollector | None = None,
    ) -> None:
        """Initialize the parser.

        Args:
            path: Path to the context file (default: /var/run/one-context/one_env)
            error_collector: Optional error collector for graceful error handling
        """
        self.path = Path(path)
        self.variables: dict[str, str] = {}
        self.error_collector = error_collector

    def parse(self) -> RouterConfig:
        """Parse the context file and return a validated RouterConfig.

        Returns:
            RouterConfig: Validated router configuration

        Raises:
            FileNotFoundError: If the context file does not exist
            ValueError: If the context file is malformed or contains invalid data
        """
        self._read_variables()

        # Parse each configuration section
        interfaces = self._parse_interfaces()
        aliases = self._parse_aliases(interfaces)
        routes = self._parse_routes()
        ospf = self._parse_ospf()
        dhcp = self._parse_dhcp()
        nat = self._parse_nat()
        firewall = self._parse_firewall()

        # Parse operational variables
        hostname = self.variables.get("HOSTNAME")
        ssh_public_key = self.variables.get("SSH_PUBLIC_KEY")
        onecontext_mode = self._parse_onecontext_mode()

        # Parse escape hatches
        start_config = self.variables.get("START_CONFIG")
        start_script = self.variables.get("START_SCRIPT")
        start_script_timeout = self._parse_start_script_timeout()

        # Build and validate complete configuration
        return RouterConfig(
            hostname=hostname,
            ssh_public_key=ssh_public_key,
            onecontext_mode=onecontext_mode,
            interfaces=interfaces,
            aliases=aliases,
            routes=routes,
            ospf=ospf,
            dhcp=dhcp,
            nat=nat,
            firewall=firewall,
            start_config=start_config,
            start_script=start_script,
            start_script_timeout=start_script_timeout,
        )

    def _read_variables(self) -> None:
        """Read and parse shell variable assignments from the context file.

        The file format is shell variable assignments:
            VAR_NAME="value"
            MULTILINE_VAR="line1
            line2"

        Raises:
            FileNotFoundError: If the context file does not exist
            ValueError: If the file is malformed
        """
        if not self.path.exists():
            raise FileNotFoundError(f"Context file not found: {self.path}")

        content = self.path.read_text()
        self.variables = self._parse_shell_variables(content)

    def _parse_shell_variables(self, content: str) -> dict[str, str]:
        """Parse shell variable assignments into a dictionary.

        Args:
            content: Shell script content with variable assignments

        Returns:
            Dictionary mapping variable names to values
        """
        variables: dict[str, str] = {}
        lines = content.splitlines()
        i = 0

        while i < len(lines):
            line = lines[i].strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                i += 1
                continue

            # Match variable assignment: VAR="value" or VAR='value'
            match = re.match(r'^([A-Z_][A-Z0-9_]*)=(["\']?)(.*)', line)
            if not match:
                i += 1
                continue

            var_name = match.group(1)
            quote = match.group(2)
            rest = match.group(3)

            if not quote:
                # Unquoted value (ends at first whitespace)
                parts = rest.split()
                value = parts[0] if parts else ""
                variables[var_name] = value
                i += 1
            else:
                # Quoted value - may span multiple lines
                value_parts = []
                current_line = rest

                # Find closing quote, handling escapes
                end_idx = self._find_closing_quote(current_line, quote)
                if end_idx is not None:
                    # Quote closes on same line
                    value_parts.append(current_line[:end_idx])
                    variables[var_name] = self._process_escapes("".join(value_parts), quote)
                    i += 1
                else:
                    # Multi-line value
                    value_parts.append(current_line)
                    i += 1

                    # Continue reading until we find the closing quote
                    while i < len(lines):
                        current_line = lines[i]
                        end_idx = self._find_closing_quote(current_line, quote)
                        if end_idx is not None:
                            value_parts.append("\n")
                            value_parts.append(current_line[:end_idx])
                            variables[var_name] = self._process_escapes("".join(value_parts), quote)
                            i += 1
                            break
                        else:
                            value_parts.append("\n")
                            value_parts.append(current_line)
                            i += 1

        return variables

    def _find_closing_quote(self, text: str, quote: str) -> int | None:
        """Find the closing quote position, accounting for escape sequences.

        Args:
            text: Text to search for closing quote
            quote: Quote character to search for (" or ')

        Returns:
            Index of closing quote, or None if not found
        """
        i = 0
        while i < len(text):
            if text[i] == "\\":
                # Skip escaped character (with bounds check)
                if i + 1 < len(text):
                    i += 2
                else:
                    # Trailing backslash, move past it
                    i += 1
            elif text[i] == quote:
                return i
            else:
                i += 1
        return None

    def _process_escapes(self, value: str, quote: str) -> str:
        """Process escape sequences in a quoted string.

        Handles:
        - \\" -> " (in double quotes)
        - \\' -> ' (in single quotes)
        - \\\\ -> \\

        Args:
            value: String with potential escape sequences
            quote: Quote character used (" or ')

        Returns:
            String with escapes processed
        """
        result = []
        i = 0
        while i < len(value):
            if value[i] == "\\":
                if i + 1 < len(value):
                    next_char = value[i + 1]
                    if next_char == quote:
                        # Escaped quote
                        result.append(quote)
                        i += 2
                    elif next_char == "\\":
                        # Escaped backslash
                        result.append("\\")
                        i += 2
                    else:
                        # Not a recognized escape, keep backslash
                        result.append("\\")
                        i += 1
                else:
                    # Backslash at end of string
                    result.append("\\")
                    i += 1
            else:
                result.append(value[i])
                i += 1
        return "".join(result)

    def _parse_interfaces(self) -> list[InterfaceConfig]:
        """Parse ETHx_* variables into InterfaceConfig objects.

        Returns:
            List of interface configurations
        """
        interfaces: list[InterfaceConfig] = []

        # Find all ETHx interfaces by looking for ETHx_IP variables
        eth_numbers = set()
        for var_name in self.variables:
            match = re.match(r"^ETH(\d+)_IP$", var_name)
            if match:
                eth_numbers.add(int(match.group(1)))

        # Parse each interface
        for eth_num in sorted(eth_numbers):
            prefix = f"ETH{eth_num}"
            ip = self.variables.get(f"{prefix}_IP")

            # Skip if no IP (shouldn't happen given how we found it, but be safe)
            if not ip:
                continue

            mask = self.variables.get(f"{prefix}_MASK")
            if not mask:
                raise ValueError(f"Interface {prefix} has IP but no MASK")

            gateway = self.variables.get(f"{prefix}_GATEWAY")
            dns = self.variables.get(f"{prefix}_DNS")
            mtu_str = self.variables.get(f"{prefix}_MTU")
            management_str = self.variables.get(f"{prefix}_VROUTER_MANAGEMENT")

            # Parse MTU
            mtu = int(mtu_str) if mtu_str else None

            # Parse management flag
            management = management_str == "YES" if management_str else False

            # Convert empty strings to None for optional IPv4Address fields
            # This prevents Pydantic validation errors when OpenNebula provides empty strings
            gateway_value = gateway if gateway else None
            dns_value = dns if dns else None

            interfaces.append(
                InterfaceConfig(
                    name=f"eth{eth_num}",
                    ip=ip,  # type: ignore[arg-type]  # Pydantic converts str to IPv4Address
                    mask=mask,
                    gateway=gateway_value,  # type: ignore[arg-type]  # Pydantic converts str to IPv4Address
                    dns=dns_value,  # type: ignore[arg-type]  # Pydantic converts str to IPv4Address
                    mtu=mtu,
                    management=management,
                )
            )

        return interfaces

    def _parse_aliases(self, interfaces: list[InterfaceConfig]) -> list[AliasConfig]:
        """Parse ETHx_ALIASy_* variables into AliasConfig objects.

        Args:
            interfaces: List of parsed interfaces (for mask fallback)

        Returns:
            List of alias configurations
        """
        aliases: list[AliasConfig] = []

        # Find all aliases by looking for ETHx_ALIASy_IP variables
        alias_pattern = re.compile(r"^ETH(\d+)_ALIAS(\d+)_IP$")
        alias_keys = set()

        for var_name in self.variables:
            match = alias_pattern.match(var_name)
            if match:
                eth_num = int(match.group(1))
                alias_num = int(match.group(2))
                alias_keys.add((eth_num, alias_num))

        # Parse each alias
        for eth_num, alias_num in sorted(alias_keys):
            interface_name = f"eth{eth_num}"
            prefix = f"ETH{eth_num}_ALIAS{alias_num}"

            ip = self.variables.get(f"{prefix}_IP")
            if not ip:
                continue

            # Mask may be empty due to OpenNebula bug
            mask = self.variables.get(f"{prefix}_MASK")
            if mask == "":
                mask = None

            # If no mask, we'll let the model handle the fallback using the parent interface mask
            # But we need to ensure the mask is None, not empty string
            aliases.append(
                AliasConfig(
                    interface=interface_name,
                    ip=ip,  # type: ignore[arg-type]  # Pydantic converts str to IPv4Address
                    mask=mask,
                )
            )

        return aliases

    def _parse_onecontext_mode(self) -> OnecontextMode:
        """Parse ONECONTEXT_MODE variable.

        Returns:
            OnecontextMode enum value (defaults to STATELESS)
        """
        mode_str = self.variables.get("ONECONTEXT_MODE", "stateless").lower()
        try:
            return OnecontextMode(mode_str)
        except ValueError:
            # Default to stateless if invalid value
            return OnecontextMode.STATELESS

    def _parse_start_script_timeout(self) -> int:
        """Parse START_SCRIPT_TIMEOUT variable.

        Returns:
            Timeout in seconds (defaults to 300)
        """
        timeout_str = self.variables.get("START_SCRIPT_TIMEOUT")
        if not timeout_str:
            return 300  # Default: 5 minutes

        try:
            timeout = int(timeout_str)
            # Validation will be done by Pydantic model
            return timeout
        except ValueError:
            # Invalid value, use default
            return 300

    def _parse_json_variable(self, var_name: str, model_class: type[T]) -> T | None:
        """Parse a JSON variable and validate with a Pydantic model.

        Args:
            var_name: Name of the variable containing JSON
            model_class: Pydantic model class to validate against

        Returns:
            Validated model instance or None if variable not present or parsing failed

        Raises:
            ValueError: If JSON is malformed or validation fails (only when error_collector is None)
        """
        json_str = self.variables.get(var_name)
        if not json_str:
            return None

        try:
            data = json.loads(json_str)
            return model_class.model_validate(data)
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON in {var_name}"
            if self.error_collector:
                self.error_collector.add_error(
                    section=var_name,
                    message=error_msg,
                    exception=e,
                    severity=ErrorSeverity.ERROR,
                )
                return None
            raise ValueError(f"{error_msg}: {e}") from e
        except Exception as e:
            error_msg = f"Validation error in {var_name}"
            if self.error_collector:
                self.error_collector.add_error(
                    section=var_name,
                    message=error_msg,
                    exception=e,
                    severity=ErrorSeverity.ERROR,
                )
                return None
            raise ValueError(f"{error_msg}: {e}") from e

    def _parse_routes(self) -> RoutesConfig | None:
        """Parse ROUTES_JSON variable.

        Returns:
            RoutesConfig or None if not present
        """
        return self._parse_json_variable("ROUTES_JSON", RoutesConfig)

    def _parse_ospf(self) -> OspfConfig | None:
        """Parse OSPF_JSON variable.

        Returns:
            OspfConfig or None if not present
        """
        return self._parse_json_variable("OSPF_JSON", OspfConfig)

    def _parse_dhcp(self) -> DhcpConfig | None:
        """Parse DHCP_JSON variable.

        Returns:
            DhcpConfig or None if not present
        """
        return self._parse_json_variable("DHCP_JSON", DhcpConfig)

    def _parse_nat(self) -> NatConfig | None:
        """Parse NAT_JSON variable.

        Returns:
            NatConfig or None if not present
        """
        return self._parse_json_variable("NAT_JSON", NatConfig)

    def _parse_firewall(self) -> FirewallConfig | None:
        """Parse FIREWALL_JSON variable.

        Returns:
            FirewallConfig or None if not present
        """
        return self._parse_json_variable("FIREWALL_JSON", FirewallConfig)


def parse_context(
    path: str = "/var/run/one-context/one_env",
    error_collector: ErrorCollector | None = None,
) -> RouterConfig:
    """Parse ONE context file and return validated RouterConfig.

    This is a convenience function that creates a ContextParser and calls parse().

    Args:
        path: Path to the context file (default: /var/run/one-context/one_env)
        error_collector: Optional error collector for graceful error handling

    Returns:
        RouterConfig: Validated router configuration

    Raises:
        FileNotFoundError: If the context file does not exist
        ValueError: If the context file is malformed or contains invalid data
                   (only when error_collector is None)
    """
    parser = ContextParser(path, error_collector=error_collector)
    return parser.parse()
