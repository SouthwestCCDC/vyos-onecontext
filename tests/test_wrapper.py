"""Unit tests for VyOS configuration wrapper."""

from unittest.mock import ANY, MagicMock, patch

import pytest

from vyos_onecontext.wrapper import VyOSConfigError, VyOSConfigSession


class TestVyOSConfigSession:
    """Tests for VyOSConfigSession class."""

    def test_init_default_path(self) -> None:
        """Test that default wrapper path is set correctly."""
        session = VyOSConfigSession()
        assert session.wrapper_path == "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper"
        assert session._in_session is False

    def test_init_custom_path(self) -> None:
        """Test that custom wrapper path can be set."""
        session = VyOSConfigSession(wrapper_path="/custom/path/wrapper")
        assert session.wrapper_path == "/custom/path/wrapper"

    @patch("subprocess.run")
    def test_begin_success(self, mock_run: MagicMock) -> None:
        """Test successful session begin."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        session = VyOSConfigSession(wrapper_path="/test/wrapper")

        session.begin()

        mock_run.assert_called_once_with(
            ["/test/wrapper", "begin"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=ANY,
        )
        assert session._in_session is True

    @patch("subprocess.run")
    def test_begin_failure(self, mock_run: MagicMock) -> None:
        """Test session begin failure after all retries exhausted."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Session already active",
        )
        session = VyOSConfigSession(wrapper_path="/test/wrapper")

        with pytest.raises(VyOSConfigError, match="Failed to begin configuration session"):
            session.begin(max_retries=3, initial_delay=0.01)

        # Should have retried 3 times
        assert mock_run.call_count == 3
        assert session._in_session is False

    @patch("time.sleep")
    @patch("subprocess.run")
    def test_begin_retry_success(self, mock_run: MagicMock, mock_sleep: MagicMock) -> None:
        """Test session begin succeeds after retries."""
        # First attempt fails, second succeeds
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr="Backend not ready"),
            MagicMock(returncode=0, stdout="", stderr=""),
        ]
        session = VyOSConfigSession(wrapper_path="/test/wrapper")

        session.begin(max_retries=3, initial_delay=0.01)

        # Should have tried twice
        assert mock_run.call_count == 2
        assert session._in_session is True
        # Should have slept once between attempts
        mock_sleep.assert_called_once_with(0.01)

    @patch("subprocess.run")
    def test_begin_already_in_session(self, mock_run: MagicMock) -> None:
        """Test that begin() warns when already in session."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        session = VyOSConfigSession(wrapper_path="/test/wrapper")
        session._in_session = True

        session.begin()

        # Should not call wrapper again
        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_end_success(self, mock_run: MagicMock) -> None:
        """Test successful session end."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        session = VyOSConfigSession(wrapper_path="/test/wrapper")
        session._in_session = True

        session.end()

        mock_run.assert_called_once_with(
            ["/test/wrapper", "end"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=ANY,
        )
        assert session._in_session is False

    @patch("subprocess.run")
    def test_end_not_in_session(self, mock_run: MagicMock) -> None:
        """Test that end() warns when not in session."""
        session = VyOSConfigSession(wrapper_path="/test/wrapper")

        session.end()

        # Should not call wrapper
        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_set_success(self, mock_run: MagicMock) -> None:
        """Test successful set command."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        session = VyOSConfigSession(wrapper_path="/test/wrapper")
        session._in_session = True

        session.set(["system", "host-name", "router01"])

        mock_run.assert_called_once_with(
            ["/test/wrapper", "set", "system", "host-name", "router01"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=ANY,
        )

    @patch("subprocess.run")
    def test_set_empty_path(self, mock_run: MagicMock) -> None:
        """Test that set() raises ValueError for empty path."""
        session = VyOSConfigSession(wrapper_path="/test/wrapper")
        session._in_session = True

        with pytest.raises(ValueError, match="cannot be empty"):
            session.set([])

        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_set_not_in_session(self, mock_run: MagicMock) -> None:
        """Test that set() raises error when not in session."""
        session = VyOSConfigSession(wrapper_path="/test/wrapper")

        with pytest.raises(VyOSConfigError, match="outside of a session"):
            session.set(["system", "host-name", "router01"])

        mock_run.assert_not_called()

    @patch("subprocess.run")
    def test_delete_success(self, mock_run: MagicMock) -> None:
        """Test successful delete command."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        session = VyOSConfigSession(wrapper_path="/test/wrapper")
        session._in_session = True

        session.delete(["system", "host-name"])

        mock_run.assert_called_once_with(
            ["/test/wrapper", "delete", "system", "host-name"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=ANY,
        )

    @patch("subprocess.run")
    def test_delete_empty_path(self, mock_run: MagicMock) -> None:
        """Test that delete() raises ValueError for empty path."""
        session = VyOSConfigSession(wrapper_path="/test/wrapper")
        session._in_session = True

        with pytest.raises(ValueError, match="cannot be empty"):
            session.delete([])

    @patch("subprocess.run")
    def test_delete_not_in_session(self, mock_run: MagicMock) -> None:
        """Test that delete() raises error when not in session."""
        session = VyOSConfigSession(wrapper_path="/test/wrapper")

        with pytest.raises(VyOSConfigError, match="outside of a session"):
            session.delete(["system", "host-name"])

    @patch("subprocess.run")
    def test_commit_success(self, mock_run: MagicMock) -> None:
        """Test successful commit."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        session = VyOSConfigSession(wrapper_path="/test/wrapper")
        session._in_session = True

        session.commit()

        mock_run.assert_called_once_with(
            ["/test/wrapper", "commit"],
            capture_output=True,
            text=True,
            check=False,
            timeout=600,
            env=ANY,
        )

    @patch("subprocess.run")
    def test_commit_not_in_session(self, mock_run: MagicMock) -> None:
        """Test that commit() raises error when not in session."""
        session = VyOSConfigSession(wrapper_path="/test/wrapper")

        with pytest.raises(VyOSConfigError, match="outside of a session"):
            session.commit()

    @patch("time.sleep")
    @patch("subprocess.run")
    def test_commit_retry_success(self, mock_run: MagicMock, mock_sleep: MagicMock) -> None:
        """Test commit succeeds after retries."""
        # First two attempts fail with "Unknown error", third succeeds
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr=""),  # Unknown error
            MagicMock(returncode=1, stdout="", stderr=""),  # Unknown error
            MagicMock(returncode=0, stdout="", stderr=""),  # Success
        ]
        session = VyOSConfigSession(wrapper_path="/test/wrapper")
        session._in_session = True

        session.commit(max_retries=3, initial_delay=0.01)

        # Should have tried 3 times
        assert mock_run.call_count == 3
        # Should have slept twice between attempts
        assert mock_sleep.call_count == 2

    @patch("subprocess.run")
    def test_commit_failure_after_retries(self, mock_run: MagicMock) -> None:
        """Test commit fails after all retries exhausted."""
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
        session = VyOSConfigSession(wrapper_path="/test/wrapper")
        session._in_session = True

        with pytest.raises(VyOSConfigError, match="Failed to commit configuration"):
            session.commit(max_retries=3, initial_delay=0.01)

        # Should have retried 3 times
        assert mock_run.call_count == 3

    @patch("subprocess.run")
    def test_save_success(self, mock_run: MagicMock) -> None:
        """Test successful save."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        session = VyOSConfigSession(wrapper_path="/test/wrapper")

        session.save()

        mock_run.assert_called_once_with(
            ["/test/wrapper", "save"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=ANY,
        )

    @patch("subprocess.run")
    def test_context_manager_success(self, mock_run: MagicMock) -> None:
        """Test context manager with successful operations."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        with VyOSConfigSession(wrapper_path="/test/wrapper") as session:
            session.set(["system", "host-name", "router01"])

        # Should have called: begin, set, commit, end
        assert mock_run.call_count == 4
        calls = [call[0][0] for call in mock_run.call_args_list]
        assert calls[0] == ["/test/wrapper", "begin"]
        assert calls[1] == ["/test/wrapper", "set", "system", "host-name", "router01"]
        assert calls[2] == ["/test/wrapper", "commit"]
        assert calls[3] == ["/test/wrapper", "end"]

    @patch("subprocess.run")
    def test_context_manager_exception(self, mock_run: MagicMock) -> None:
        """Test context manager when exception occurs."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        with (
            pytest.raises(RuntimeError, match="Test error"),
            VyOSConfigSession(wrapper_path="/test/wrapper") as session,
        ):
            session.set(["system", "host-name", "router01"])
            raise RuntimeError("Test error")

        # Should have called: begin, set, end (no commit due to exception)
        assert mock_run.call_count == 3
        calls = [call[0][0] for call in mock_run.call_args_list]
        assert calls[0] == ["/test/wrapper", "begin"]
        assert calls[1] == ["/test/wrapper", "set", "system", "host-name", "router01"]
        assert calls[2] == ["/test/wrapper", "end"]

    @patch("subprocess.run")
    def test_wrapper_not_found(self, mock_run: MagicMock) -> None:
        """Test handling of missing wrapper executable."""
        mock_run.side_effect = FileNotFoundError()
        session = VyOSConfigSession(wrapper_path="/nonexistent/wrapper")

        with pytest.raises(VyOSConfigError, match="not found"):
            session.begin()

    @patch("subprocess.run")
    def test_wrapper_os_error(self, mock_run: MagicMock) -> None:
        """Test handling of OS errors when executing wrapper."""
        mock_run.side_effect = OSError("Permission denied")
        session = VyOSConfigSession(wrapper_path="/test/wrapper")

        with pytest.raises(VyOSConfigError, match="Permission denied"):
            session.begin()

    @patch("subprocess.run")
    def test_wrapper_timeout(self, mock_run: MagicMock) -> None:
        """Test handling of subprocess timeout."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=[
                "/test/wrapper",
                "set",
                "interfaces",
                "ethernet",
                "eth0",
                "address",
                "10.0.0.1/24",
            ],
            timeout=30,
        )
        session = VyOSConfigSession(wrapper_path="/test/wrapper")
        session._in_session = True

        with pytest.raises(
            VyOSConfigError,
            match=r"timed out after 30s: /test/wrapper set interfaces ethernet "
            r"eth0 address 10\.0\.0\.1/24",
        ):
            session.set(["interfaces", "ethernet", "eth0", "address", "10.0.0.1/24"])

    @patch("subprocess.run")
    def test_run_commands(self, mock_run: MagicMock) -> None:
        """Test run_commands method."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        session = VyOSConfigSession(wrapper_path="/test/wrapper")
        session._in_session = True

        commands = [
            "set system host-name router01",
            "system option performance throughput",  # Without 'set' prefix
        ]
        session.run_commands(commands)

        assert mock_run.call_count == 2
        calls = [call[0][0] for call in mock_run.call_args_list]
        assert calls[0] == ["/test/wrapper", "set", "system", "host-name", "router01"]
        assert calls[1] == ["/test/wrapper", "set", "system", "option", "performance", "throughput"]

    @patch("subprocess.run")
    def test_run_commands_with_quoted_strings(self, mock_run: MagicMock) -> None:
        """Test run_commands properly handles quoted strings with spaces."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        session = VyOSConfigSession(wrapper_path="/test/wrapper")
        session._in_session = True

        commands = [
            "set system host-name 'test router'",
            'set system domain-name "example.com"',
            "set system login banner 'Welcome to VyOS'",
        ]
        session.run_commands(commands)

        assert mock_run.call_count == 3
        calls = [call[0][0] for call in mock_run.call_args_list]
        # shlex.split removes quotes and treats content as single argument
        assert calls[0] == ["/test/wrapper", "set", "system", "host-name", "test router"]
        assert calls[1] == ["/test/wrapper", "set", "system", "domain-name", "example.com"]
        assert calls[2] == ["/test/wrapper", "set", "system", "login", "banner", "Welcome to VyOS"]

    @patch("subprocess.run")
    def test_run_commands_with_special_chars(self, mock_run: MagicMock) -> None:
        """Test run_commands handles special characters in quoted strings."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        session = VyOSConfigSession(wrapper_path="/test/wrapper")
        session._in_session = True

        commands = [
            "set system description 'Router-01 (Production)'",
            "set system note 'Key: value=123'",
        ]
        session.run_commands(commands)

        assert mock_run.call_count == 2
        calls = [call[0][0] for call in mock_run.call_args_list]
        assert calls[0] == [
            "/test/wrapper",
            "set",
            "system",
            "description",
            "Router-01 (Production)",
        ]
        assert calls[1] == ["/test/wrapper", "set", "system", "note", "Key: value=123"]

    @patch("subprocess.run")
    def test_run_commands_with_newlines_in_strings(self, mock_run: MagicMock) -> None:
        """Test run_commands handles literal newlines within quoted strings."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        session = VyOSConfigSession(wrapper_path="/test/wrapper")
        session._in_session = True

        # Command with literal newline inside quoted string
        # shlex.split() should handle this and preserve the newline
        commands = [
            "set system login banner 'Line 1\nLine 2\nLine 3'",
        ]
        session.run_commands(commands)

        assert mock_run.call_count == 1
        calls = [call[0][0] for call in mock_run.call_args_list]
        # shlex.split should preserve the newline characters
        assert calls[0] == [
            "/test/wrapper",
            "set",
            "system",
            "login",
            "banner",
            "Line 1\nLine 2\nLine 3",
        ]

    @patch("subprocess.run")
    def test_run_commands_multiple_with_newlines(self, mock_run: MagicMock) -> None:
        """Test run_commands with multiple commands containing newlines."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        session = VyOSConfigSession(wrapper_path="/test/wrapper")
        session._in_session = True

        commands = [
            "set system host-name router01",
            "set system description 'Main router\nfor building A'",
            "set system contact 'Admin team\nEmail: admin@example.com'",
        ]
        session.run_commands(commands)

        assert mock_run.call_count == 3
        calls = [call[0][0] for call in mock_run.call_args_list]
        assert calls[0] == ["/test/wrapper", "set", "system", "host-name", "router01"]
        assert calls[1] == [
            "/test/wrapper",
            "set",
            "system",
            "description",
            "Main router\nfor building A",
        ]
        assert calls[2] == [
            "/test/wrapper",
            "set",
            "system",
            "contact",
            "Admin team\nEmail: admin@example.com",
        ]

    @patch("subprocess.run")
    def test_run_commands_with_tabs_and_newlines(self, mock_run: MagicMock) -> None:
        """Test run_commands handles tabs and newlines in quoted strings."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        session = VyOSConfigSession(wrapper_path="/test/wrapper")
        session._in_session = True

        commands = [
            "set system note 'Item 1:\tValue A\nItem 2:\tValue B'",
        ]
        session.run_commands(commands)

        assert mock_run.call_count == 1
        calls = [call[0][0] for call in mock_run.call_args_list]
        assert calls[0] == [
            "/test/wrapper",
            "set",
            "system",
            "note",
            "Item 1:\tValue A\nItem 2:\tValue B",
        ]


class TestVyOSConfigSessionVerifyGroup:
    """Tests for group verification."""

    @patch("os.getgroups")
    @patch("os.getegid")
    @patch("grp.getgrnam")
    def test_verify_group_in_supplementary(
        self,
        mock_getgrnam: MagicMock,
        mock_getegid: MagicMock,
        mock_getgroups: MagicMock,
    ) -> None:
        """Test verify_group when vyattacfg is in supplementary groups."""
        mock_getgrnam.return_value = MagicMock(gr_gid=1001)
        mock_getegid.return_value = 1000
        mock_getgroups.return_value = [1000, 1001, 1002]

        session = VyOSConfigSession()
        assert session.verify_group() is True

    @patch("os.getgroups")
    @patch("os.getegid")
    @patch("grp.getgrnam")
    def test_verify_group_is_effective(
        self,
        mock_getgrnam: MagicMock,
        mock_getegid: MagicMock,
        mock_getgroups: MagicMock,
    ) -> None:
        """Test verify_group when vyattacfg is effective GID."""
        mock_getgrnam.return_value = MagicMock(gr_gid=1001)
        mock_getegid.return_value = 1001
        mock_getgroups.return_value = [1000, 1002]

        session = VyOSConfigSession()
        assert session.verify_group() is True

    @patch("os.getgroups")
    @patch("os.getegid")
    @patch("grp.getgrnam")
    def test_verify_group_not_present(
        self,
        mock_getgrnam: MagicMock,
        mock_getegid: MagicMock,
        mock_getgroups: MagicMock,
    ) -> None:
        """Test verify_group when vyattacfg is not present."""
        mock_getgrnam.return_value = MagicMock(gr_gid=1001)
        mock_getegid.return_value = 1000
        mock_getgroups.return_value = [1000, 1002, 1003]

        session = VyOSConfigSession()
        assert session.verify_group() is False

    @patch("grp.getgrnam")
    def test_verify_group_no_vyattacfg(self, mock_getgrnam: MagicMock) -> None:
        """Test verify_group when vyattacfg group doesn't exist."""
        mock_getgrnam.side_effect = KeyError("vyattacfg")

        session = VyOSConfigSession()
        assert session.verify_group() is False
