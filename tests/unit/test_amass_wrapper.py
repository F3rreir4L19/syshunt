from subprocess import CompletedProcess
from unittest.mock import patch

from tools.amass_wrapper import AmassWrapper
from tools.base import ToolOptions


def test_amass_builds_passive_command() -> None:
    command = AmassWrapper().build_command("example.com", ToolOptions())

    assert command == ["amass", "enum", "-passive", "-d", "example.com"]


def test_amass_builds_command_with_extra_args() -> None:
    command = AmassWrapper().build_command(
        "example.com", ToolOptions(extra_args=["-brute"])
    )

    assert command == ["amass", "enum", "-passive", "-d", "example.com", "-brute"]


def test_amass_parses_unique_lowercase_subdomains() -> None:
    output = "API.example.com\nsub.example.com\nAPI.example.com\n\n"

    parsed = AmassWrapper().parse_output(output)

    assert parsed == ["api.example.com", "sub.example.com"]


def test_amass_run_uses_mocked_subprocess() -> None:
    with patch("tools.base.subprocess.run") as run:
        run.return_value = CompletedProcess(
            args=["amass"],
            returncode=0,
            stdout="mail.example.com\napi.example.com\n",
            stderr="",
        )

        result = AmassWrapper().run("example.com")

    assert result.success is True
    assert result.parsed_data == ["api.example.com", "mail.example.com"]
    run.assert_called_once()


def test_amass_run_returns_failure_on_nonzero_exit() -> None:
    with patch("tools.base.subprocess.run") as run:
        run.return_value = CompletedProcess(
            args=["amass"], returncode=1, stdout="", stderr="error"
        )

        result = AmassWrapper().run("example.com")

    assert result.success is False
    assert result.error is not None
