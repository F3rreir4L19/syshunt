from subprocess import CompletedProcess
from unittest.mock import patch

from tools.base import ToolOptions
from tools.gau_wrapper import GauWrapper


def test_gau_builds_expected_command() -> None:
    command = GauWrapper().build_command("example.com", ToolOptions())

    assert command == ["gau", "--threads", "5", "example.com"]


def test_gau_builds_command_with_extra_args() -> None:
    command = GauWrapper().build_command(
        "example.com", ToolOptions(extra_args=["--subs"])
    )

    assert "--subs" in command


def test_gau_parses_http_urls_and_deduplicates() -> None:
    output = (
        "https://example.com/old-page\n"
        "https://example.com/archive\n"
        "https://example.com/old-page\n"  # duplicate
        "ftp://example.com/file\n"  # non-http, excluded
        "\n"
    )

    parsed = GauWrapper().parse_output(output)

    assert parsed == [
        "https://example.com/archive",
        "https://example.com/old-page",
    ]


def test_gau_run_uses_mocked_subprocess() -> None:
    with patch("tools.base.subprocess.run") as run:
        run.return_value = CompletedProcess(
            args=["gau"],
            returncode=0,
            stdout="https://example.com/a\nhttps://example.com/b\n",
            stderr="",
        )

        result = GauWrapper().run("example.com")

    assert result.success is True
    assert result.parsed_data == [
        "https://example.com/a",
        "https://example.com/b",
    ]
    run.assert_called_once()


def test_gau_returns_empty_on_no_output() -> None:
    assert GauWrapper().parse_output("") == []
