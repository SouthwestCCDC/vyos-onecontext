"""Unit tests for the __main__ entry point."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vyos_onecontext.__main__ import (
    EXIT_CONFIG_ERROR,
    EXIT_FROZEN,
    EXIT_NO_CONTEXT,
    EXIT_PARSE_ERROR,
    EXIT_SUCCESS,
    apply_configuration,
    create_freeze_marker,
    is_frozen,
    main,
    run_start_script,
)


class TestIsFrozen:
    """Tests for is_frozen function."""

    def test_is_frozen_true(self, tmp_path: Path) -> None:
        """Test is_frozen returns True when marker exists."""
        with patch("vyos_onecontext.__main__.FREEZE_MARKER_PATH", str(tmp_path / "frozen")):
            marker = tmp_path / "frozen"
            marker.touch()
            assert is_frozen() is True

    def test_is_frozen_false(self, tmp_path: Path) -> None:
        """Test is_frozen returns False when marker does not exist."""
        with patch("vyos_onecontext.__main__.FREEZE_MARKER_PATH", str(tmp_path / "frozen")):
            assert is_frozen() is False


class TestCreateFreezeMarker:
    """Tests for create_freeze_marker function."""

    def test_create_freeze_marker(self, tmp_path: Path) -> None:
        """Test create_freeze_marker creates the marker file."""
        marker_path = tmp_path / "frozen"
        with patch("vyos_onecontext.__main__.FREEZE_MARKER_PATH", str(marker_path)):
            create_freeze_marker()
            assert marker_path.exists()


class TestRunStartScript:
    """Tests for run_start_script function."""

    def test_run_start_script_success(self) -> None:
        """Test successful START_SCRIPT execution."""
        script = "#!/bin/bash\necho 'hello world'"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="hello world", stderr="")
            run_start_script(script)
            mock_run.assert_called_once()
            # Script should be passed to bash
            call_args = mock_run.call_args[0][0]
            assert call_args[0] == "/bin/bash"

    def test_run_start_script_failure(self) -> None:
        """Test START_SCRIPT failure handling."""
        script = "#!/bin/bash\nexit 1"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
            # Should not raise, just log the error
            run_start_script(script)

    def test_run_start_script_from_file_path(self, tmp_path: Path) -> None:
        """Test START_SCRIPT execution from file path."""
        # Create a test script file
        script_file = tmp_path / "test_script.sh"
        script_file.write_text("#!/bin/bash\necho 'from file'")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="from file", stderr="")
            run_start_script(str(script_file))
            mock_run.assert_called_once()
            # Should execute the file directly
            call_args = mock_run.call_args[0][0]
            assert call_args[1] == str(script_file)

    def test_run_start_script_inline_vs_path(self, tmp_path: Path) -> None:
        """Test that inline scripts with path-like content are handled correctly."""
        # Even if content starts with /, if file doesn't exist, treat as inline
        script = "/nonexistent/script.sh\necho 'inline'"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            run_start_script(script)
            # Should create temp file since path doesn't exist
            call_args = mock_run.call_args[0][0]
            # Should NOT be the literal path from script content
            assert call_args[1] != "/nonexistent/script.sh"

    def test_run_start_script_timeout(self) -> None:
        """Test START_SCRIPT timeout handling."""
        script = "#!/bin/bash\nsleep 100"
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("/bin/bash", 1)
            # Should not raise, just log the timeout
            run_start_script(script, timeout=1)

    def test_run_start_script_default_timeout(self) -> None:
        """Test START_SCRIPT uses 300 second default timeout."""
        script = "#!/bin/bash\necho 'test'"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="test", stderr="")
            run_start_script(script)
            # Verify default timeout of 300 seconds is applied
            assert mock_run.call_args[1]["timeout"] == 300

    def test_run_start_script_custom_timeout(self) -> None:
        """Test START_SCRIPT with custom timeout value."""
        script = "#!/bin/bash\necho 'test'"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="test", stderr="")
            run_start_script(script, timeout=60)
            # Verify timeout parameter was passed
            assert mock_run.call_args[1]["timeout"] == 60

    def test_run_start_script_path_with_leading_whitespace(self, tmp_path: Path) -> None:
        """Test START_SCRIPT handles file paths with leading whitespace."""
        # Create a test script file
        script_file = tmp_path / "test_script.sh"
        script_file.write_text("#!/bin/bash\necho 'from file'")

        # Add leading whitespace to the path
        script_content = f"  {script_file}"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="from file", stderr="")
            run_start_script(script_content)
            mock_run.assert_called_once()
            # Should execute the file directly (whitespace stripped)
            call_args = mock_run.call_args[0][0]
            assert call_args[1] == str(script_file)

    def test_run_start_script_path_with_trailing_whitespace(self, tmp_path: Path) -> None:
        """Test START_SCRIPT handles file paths with trailing whitespace."""
        # Create a test script file
        script_file = tmp_path / "test_script.sh"
        script_file.write_text("#!/bin/bash\necho 'from file'")

        # Add trailing whitespace to the path
        script_content = f"{script_file}  "

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="from file", stderr="")
            run_start_script(script_content)
            mock_run.assert_called_once()
            # Should execute the file directly (whitespace stripped)
            call_args = mock_run.call_args[0][0]
            assert call_args[1] == str(script_file)

    def test_run_start_script_path_with_both_whitespace(self, tmp_path: Path) -> None:
        """Test START_SCRIPT handles file paths with leading and trailing whitespace."""
        # Create a test script file
        script_file = tmp_path / "test_script.sh"
        script_file.write_text("#!/bin/bash\necho 'from file'")

        # Add both leading and trailing whitespace to the path
        script_content = f"  {script_file}  "

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="from file", stderr="")
            run_start_script(script_content)
            mock_run.assert_called_once()
            # Should execute the file directly (whitespace stripped)
            call_args = mock_run.call_args[0][0]
            assert call_args[1] == str(script_file)


class TestApplyConfiguration:
    """Tests for apply_configuration function."""

    def test_apply_configuration_no_context_file(self, tmp_path: Path) -> None:
        """Test that missing context file returns EXIT_NO_CONTEXT."""
        context_path = str(tmp_path / "nonexistent")
        result = apply_configuration(context_path)
        assert result == EXIT_NO_CONTEXT

    def test_apply_configuration_frozen(self, tmp_path: Path) -> None:
        """Test that frozen state returns EXIT_FROZEN."""
        context_path = tmp_path / "context.sh"
        context_path.write_text('HOSTNAME="test-router"')
        marker_path = tmp_path / "frozen"
        marker_path.touch()

        with patch("vyos_onecontext.__main__.FREEZE_MARKER_PATH", str(marker_path)):
            result = apply_configuration(str(context_path))
            assert result == EXIT_FROZEN

    @patch("vyos_onecontext.__main__.parse_context")
    def test_apply_configuration_parse_error(
        self,
        mock_parse: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test that parse errors return EXIT_PARSE_ERROR."""
        context_path = tmp_path / "context.sh"
        context_path.write_text("INVALID")

        mock_parse.side_effect = ValueError("Parse error")

        with patch("vyos_onecontext.__main__.FREEZE_MARKER_PATH", str(tmp_path / "frozen")):
            result = apply_configuration(str(context_path))
            assert result == EXIT_PARSE_ERROR

    @patch("vyos_onecontext.__main__.VyOSConfigSession")
    @patch("vyos_onecontext.__main__.generate_config")
    @patch("vyos_onecontext.__main__.parse_context")
    def test_apply_configuration_empty_commands(
        self,
        mock_parse: MagicMock,
        mock_generate: MagicMock,
        mock_session: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test that empty commands returns EXIT_SUCCESS."""
        context_path = tmp_path / "context.sh"
        context_path.write_text('HOSTNAME="test-router"')

        mock_config = MagicMock()
        mock_config.onecontext_mode = MagicMock(value="stateless")
        mock_parse.return_value = mock_config
        mock_generate.return_value = []

        with patch("vyos_onecontext.__main__.FREEZE_MARKER_PATH", str(tmp_path / "frozen")):
            result = apply_configuration(str(context_path))
            assert result == EXIT_SUCCESS
            # Session should not be created if no commands
            mock_session.assert_not_called()

    @patch("vyos_onecontext.__main__.VyOSConfigSession")
    @patch("vyos_onecontext.__main__.generate_config")
    @patch("vyos_onecontext.__main__.parse_context")
    def test_apply_configuration_dry_run(
        self,
        mock_parse: MagicMock,
        mock_generate: MagicMock,
        mock_session: MagicMock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Test dry run mode prints commands but doesn't execute."""
        context_path = tmp_path / "context.sh"
        context_path.write_text('HOSTNAME="test-router"')

        from vyos_onecontext.models import OnecontextMode

        mock_config = MagicMock()
        mock_config.onecontext_mode = OnecontextMode.STATELESS
        mock_parse.return_value = mock_config
        mock_generate.return_value = ["set system host-name test-router"]

        with patch("vyos_onecontext.__main__.FREEZE_MARKER_PATH", str(tmp_path / "frozen")):
            result = apply_configuration(str(context_path), dry_run=True)
            assert result == EXIT_SUCCESS
            mock_session.assert_not_called()

            captured = capsys.readouterr()
            assert "Dry run" in captured.out
            assert "set system host-name test-router" in captured.out

    @patch("vyos_onecontext.__main__.VyOSConfigSession")
    @patch("vyos_onecontext.__main__.generate_config")
    @patch("vyos_onecontext.__main__.parse_context")
    def test_apply_configuration_stateless(
        self,
        mock_parse: MagicMock,
        mock_generate: MagicMock,
        mock_session_class: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test stateless mode applies config without saving."""
        context_path = tmp_path / "context.sh"
        context_path.write_text('HOSTNAME="test-router"')

        from vyos_onecontext.models import OnecontextMode

        mock_config = MagicMock()
        mock_config.onecontext_mode = OnecontextMode.STATELESS
        mock_config.start_script = None
        mock_parse.return_value = mock_config
        mock_generate.return_value = ["set system host-name test-router"]

        mock_session = MagicMock()
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)
        mock_session_class.return_value = mock_session

        with patch("vyos_onecontext.__main__.FREEZE_MARKER_PATH", str(tmp_path / "frozen")):
            result = apply_configuration(str(context_path))
            assert result == EXIT_SUCCESS
            mock_session.run_commands.assert_called_once_with(["set system host-name test-router"])
            mock_session.save.assert_not_called()

    @patch("vyos_onecontext.__main__.VyOSConfigSession")
    @patch("vyos_onecontext.__main__.generate_config")
    @patch("vyos_onecontext.__main__.parse_context")
    def test_apply_configuration_save_mode(
        self,
        mock_parse: MagicMock,
        mock_generate: MagicMock,
        mock_session_class: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test save mode applies config and saves."""
        context_path = tmp_path / "context.sh"
        context_path.write_text('HOSTNAME="test-router"')

        from vyos_onecontext.models import OnecontextMode

        mock_config = MagicMock()
        mock_config.onecontext_mode = OnecontextMode.SAVE
        mock_config.start_script = None
        mock_parse.return_value = mock_config
        mock_generate.return_value = ["set system host-name test-router"]

        mock_session = MagicMock()
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)
        mock_session_class.return_value = mock_session

        with patch("vyos_onecontext.__main__.FREEZE_MARKER_PATH", str(tmp_path / "frozen")):
            result = apply_configuration(str(context_path))
            assert result == EXIT_SUCCESS
            mock_session.save.assert_called_once()

    @patch("vyos_onecontext.__main__.create_freeze_marker")
    @patch("vyos_onecontext.__main__.VyOSConfigSession")
    @patch("vyos_onecontext.__main__.generate_config")
    @patch("vyos_onecontext.__main__.parse_context")
    def test_apply_configuration_freeze_mode(
        self,
        mock_parse: MagicMock,
        mock_generate: MagicMock,
        mock_session_class: MagicMock,
        mock_freeze: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test freeze mode applies config, saves, and creates marker."""
        context_path = tmp_path / "context.sh"
        context_path.write_text('HOSTNAME="test-router"')

        from vyos_onecontext.models import OnecontextMode

        mock_config = MagicMock()
        mock_config.onecontext_mode = OnecontextMode.FREEZE
        mock_config.start_script = None
        mock_parse.return_value = mock_config
        mock_generate.return_value = ["set system host-name test-router"]

        mock_session = MagicMock()
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)
        mock_session_class.return_value = mock_session

        with patch("vyos_onecontext.__main__.FREEZE_MARKER_PATH", str(tmp_path / "frozen")):
            result = apply_configuration(str(context_path))
            assert result == EXIT_SUCCESS
            mock_session.save.assert_called_once()
            mock_freeze.assert_called_once()

    @patch("vyos_onecontext.__main__.run_start_script")
    @patch("vyos_onecontext.__main__.VyOSConfigSession")
    @patch("vyos_onecontext.__main__.generate_config")
    @patch("vyos_onecontext.__main__.parse_context")
    def test_apply_configuration_with_start_script(
        self,
        mock_parse: MagicMock,
        mock_generate: MagicMock,
        mock_session_class: MagicMock,
        mock_run_script: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test that START_SCRIPT is executed after config."""
        context_path = tmp_path / "context.sh"
        context_path.write_text('HOSTNAME="test-router"')

        from vyos_onecontext.models import OnecontextMode

        mock_config = MagicMock()
        mock_config.onecontext_mode = OnecontextMode.STATELESS
        mock_config.start_script = "#!/bin/bash\necho hello"
        mock_parse.return_value = mock_config
        mock_generate.return_value = ["set system host-name test-router"]

        mock_session = MagicMock()
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)
        mock_session_class.return_value = mock_session

        with patch("vyos_onecontext.__main__.FREEZE_MARKER_PATH", str(tmp_path / "frozen")):
            result = apply_configuration(str(context_path))
            assert result == EXIT_SUCCESS
            mock_run_script.assert_called_once_with("#!/bin/bash\necho hello", timeout=300)

    @patch("vyos_onecontext.__main__.run_start_script")
    @patch("vyos_onecontext.__main__.VyOSConfigSession")
    @patch("vyos_onecontext.__main__.generate_config")
    @patch("vyos_onecontext.__main__.parse_context")
    def test_apply_configuration_with_start_script_custom_timeout(
        self,
        mock_parse: MagicMock,
        mock_generate: MagicMock,
        mock_session_class: MagicMock,
        mock_run_script: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test that START_SCRIPT_TIMEOUT is passed to run_start_script."""
        context_path = tmp_path / "context.sh"
        context_path.write_text('HOSTNAME="test-router"')

        from vyos_onecontext.models import OnecontextMode

        mock_config = MagicMock()
        mock_config.onecontext_mode = OnecontextMode.STATELESS
        mock_config.start_script = "#!/bin/bash\necho hello"
        mock_config.start_script_timeout = 600
        mock_parse.return_value = mock_config
        mock_generate.return_value = ["set system host-name test-router"]

        mock_session = MagicMock()
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)
        mock_session_class.return_value = mock_session

        with patch("vyos_onecontext.__main__.FREEZE_MARKER_PATH", str(tmp_path / "frozen")):
            result = apply_configuration(str(context_path))
            assert result == EXIT_SUCCESS
            mock_run_script.assert_called_once_with("#!/bin/bash\necho hello", timeout=600)

    @patch("vyos_onecontext.__main__.VyOSConfigSession")
    @patch("vyos_onecontext.__main__.generate_config")
    @patch("vyos_onecontext.__main__.parse_context")
    def test_apply_configuration_config_error(
        self,
        mock_parse: MagicMock,
        mock_generate: MagicMock,
        mock_session_class: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Test that VyOSConfigError returns EXIT_CONFIG_ERROR."""
        from vyos_onecontext.wrapper import VyOSConfigError

        context_path = tmp_path / "context.sh"
        context_path.write_text('HOSTNAME="test-router"')

        from vyos_onecontext.models import OnecontextMode

        mock_config = MagicMock()
        mock_config.onecontext_mode = OnecontextMode.STATELESS
        mock_parse.return_value = mock_config
        mock_generate.return_value = ["set system host-name test-router"]

        mock_session = MagicMock()
        mock_session.__enter__ = MagicMock(side_effect=VyOSConfigError("Config failed"))
        mock_session_class.return_value = mock_session

        with patch("vyos_onecontext.__main__.FREEZE_MARKER_PATH", str(tmp_path / "frozen")):
            result = apply_configuration(str(context_path))
            assert result == EXIT_CONFIG_ERROR


class TestMain:
    """Tests for main entry point."""

    @patch("vyos_onecontext.__main__.apply_configuration")
    def test_main_default_args(self, mock_apply: MagicMock) -> None:
        """Test main with default arguments."""
        mock_apply.return_value = EXIT_SUCCESS

        with patch("sys.argv", ["vyos_onecontext"]):
            result = main()

        assert result == EXIT_SUCCESS
        mock_apply.assert_called_once_with(
            context_path="/var/run/one-context/one_env",
            wrapper_path=None,
            dry_run=False,
        )

    @patch("vyos_onecontext.__main__.apply_configuration")
    def test_main_custom_context_path(self, mock_apply: MagicMock) -> None:
        """Test main with custom context path."""
        mock_apply.return_value = EXIT_SUCCESS

        with patch("sys.argv", ["vyos_onecontext", "/custom/path"]):
            result = main()

        assert result == EXIT_SUCCESS
        mock_apply.assert_called_once_with(
            context_path="/custom/path",
            wrapper_path=None,
            dry_run=False,
        )

    @patch("vyos_onecontext.__main__.apply_configuration")
    def test_main_dry_run(self, mock_apply: MagicMock) -> None:
        """Test main with --dry-run flag."""
        mock_apply.return_value = EXIT_SUCCESS

        with patch("sys.argv", ["vyos_onecontext", "--dry-run"]):
            result = main()

        assert result == EXIT_SUCCESS
        mock_apply.assert_called_once()
        assert mock_apply.call_args[1]["dry_run"] is True

    @patch("vyos_onecontext.__main__.apply_configuration")
    def test_main_wrapper_path(self, mock_apply: MagicMock) -> None:
        """Test main with --wrapper-path flag."""
        mock_apply.return_value = EXIT_SUCCESS

        with patch("sys.argv", ["vyos_onecontext", "--wrapper-path", "/test/wrapper"]):
            result = main()

        assert result == EXIT_SUCCESS
        mock_apply.assert_called_once()
        assert mock_apply.call_args[1]["wrapper_path"] == "/test/wrapper"
