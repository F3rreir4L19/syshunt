from subprocess import CompletedProcess
from unittest.mock import patch

from tools.base import ToolOptions
from tools.katana_wrapper import KatanaWrapper


def test_katana_builds_expected_command() -> None:
    command = KatanaWrapper().build_command("https://example.com", ToolOptions())

    assert command == [
        "katana", "-u", "https://example.com",
        "-depth", "2", "-jc", "-silent",
    ]


def test_katana_builds_command_with_extra_args() -> None:
    command = KatanaWrapper().build_command(
        "https://example.com", ToolOptions(extra_args=["-form-extraction"])
    )

    assert "-form-extraction" in command


def test_katana_parses_http_urls_only() -> None:
    output = (
        "https://example.com/page\n"
        "https://example.com/api\n"
        "not-a-url\n"
        "\n"
        "https://example.com/page\n"  # duplicate
    )

    parsed = KatanaWrapper().parse_output(output)

    assert parsed == ["https://example.com/api", "https://example.com/page"]


def test_katana_run_uses_mocked_subprocess() -> None:
    with patch("tools.base.subprocess.run") as run:
        run.return_value = CompletedProcess(
            args=["katana"],
            returncode=0,
            stdout="https://example.com/login\nhttps://example.com/admin\n",
            stderr="",
        )

        result = KatanaWrapper().run("https://example.com")

    assert result.success is True
    assert result.parsed_data == [
        "https://example.com/admin",
        "https://example.com/login",
    ]
    run.assert_called_once()


def test_katana_returns_empty_on_no_http_lines() -> None:
    assert KatanaWrapper().parse_output("INFO crawling\nDEBUG processing\n") == []
