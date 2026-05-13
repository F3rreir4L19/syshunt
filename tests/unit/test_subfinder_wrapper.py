from subprocess import CompletedProcess
from unittest.mock import patch

from tools.base import ToolOptions
from tools.subfinder_wrapper import SubfinderWrapper


def test_subfinder_builds_expected_command() -> None:
    command = SubfinderWrapper().build_command(
        "example.com",
        ToolOptions(extra_args=["-all"]),
    )

    assert command == ["subfinder", "-silent", "-d", "example.com", "-all"]


def test_subfinder_parses_unique_lowercase_subdomains() -> None:
    output = "WWW.example.com\napi.example.com\nwww.example.com\n\n"

    parsed = SubfinderWrapper().parse_output(output)

    assert parsed == ["api.example.com", "www.example.com"]


def test_subfinder_run_uses_mocked_subprocess() -> None:
    with patch("tools.base.subprocess.run") as run:
        run.return_value = CompletedProcess(
            args=["subfinder"],
            returncode=0,
            stdout="api.example.com\n",
            stderr="",
        )

        result = SubfinderWrapper().run("example.com")

    assert result.success is True
    assert result.parsed_data == ["api.example.com"]
    run.assert_called_once()
