"""Pytest configuration and fixtures for vyos-onecontext tests."""

import subprocess
from collections.abc import Callable

import pytest


@pytest.fixture
def ssh_connection() -> Callable[[str], str]:
    """Fixture providing SSH connection to integration test VM.

    Returns a callable that executes commands via SSH and returns output.

    Usage:
        def test_something(ssh_connection):
            output = ssh_connection("show version")
            assert "VyOS" in output

    Note: This fixture is only available when running integration tests
    in the QEMU test harness (run-qemu-test.sh). It will be skipped in
    normal pytest runs.

    Returns:
        Callable that takes a command string and returns stdout as string

    Raises:
        pytest.skip: If SSH connection is not available (not in QEMU harness)
    """
    import os

    # Check if we're running in the QEMU test harness
    ssh_available = os.environ.get("SSH_AVAILABLE", "0")
    if ssh_available != "1":
        pytest.skip("SSH connection not available (not running in QEMU test harness)")

    # Get SSH connection parameters from environment
    ssh_password = os.environ.get("SSH_PASSWORD", "vyos")
    ssh_port = os.environ.get("SSH_PORT", "10022")
    ssh_host = os.environ.get("SSH_HOST", "localhost")
    ssh_user = os.environ.get("SSH_USER", "vyos")

    def run_ssh_command(command: str) -> str:
        """Execute command via SSH and return output.

        Args:
            command: Shell command to execute on remote host

        Returns:
            Command stdout as string

        Raises:
            subprocess.CalledProcessError: If command exits non-zero
        """
        ssh_opts = [
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ConnectTimeout=5",
        ]

        ssh_cmd = [
            "sshpass",
            "-p",
            ssh_password,
            "ssh",
            *ssh_opts,
            "-p",
            ssh_port,
            f"{ssh_user}@{ssh_host}",
            command,
        ]

        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            check=True,
        )

        return result.stdout

    return run_ssh_command


@pytest.fixture
def sample_context() -> dict[str, str]:
    """Minimal valid context for testing.

    Returns:
        Dictionary of context variables for basic router configuration
    """
    return {
        "HOSTNAME": "test-router",
        "ETH0_IP": "10.0.1.1",
        "ETH0_MASK": "255.255.255.0",
        "ETH0_VROUTER_MANAGEMENT": "YES",
    }


@pytest.fixture
def full_context(sample_context: dict[str, str]) -> dict[str, str]:
    """Full context with all JSON extensions.

    Args:
        sample_context: Base context fixture

    Returns:
        Dictionary with complete context including JSON-encoded configs
    """
    return {
        **sample_context,
        "ROUTES_JSON": (
            '{"static":[{"interface":"eth1","destination":"0.0.0.0/0",'
            '"gateway":"10.0.1.254"}]}'
        ),
        "OSPF_JSON": '{"enabled":true,"areas":[{"id":"0.0.0.0","networks":["10.0.0.0/8"]}]}',
    }
