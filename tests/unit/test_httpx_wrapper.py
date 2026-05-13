from subprocess import CompletedProcess
from unittest.mock import patch

from tools.base import ToolOptions
from tools.httpx_wrapper import HttpxWrapper


def test_httpx_builds_expected_command() -> None:
    command = HttpxWrapper().build_command(
        "https://example.com",
        ToolOptions(extra_args=["-follow-redirects"]),
    )

    assert command == [
        "httpx",
        "-silent",
        "-json",
        "-title",
        "-tech-detect",
        "-status-code",
        "-u",
        "https://example.com",
        "-follow-redirects",
    ]


def test_httpx_parses_json_lines_and_plain_urls() -> None:
    output = (
        '{"url":"https://example.com","status_code":200,"title":"Home"}\n'
        "https://fallback.example.com\n"
    )

    parsed = HttpxWrapper().parse_output(output)

    assert parsed == [
        {"url": "https://example.com", "status_code": 200, "title": "Home"},
        {"url": "https://fallback.example.com"},
    ]


def test_httpx_run_uses_mocked_subprocess() -> None:
    with patch("tools.base.subprocess.run") as run:
        run.return_value = CompletedProcess(
            args=["httpx"],
            returncode=0,
            stdout='{"url":"https://example.com","status_code":200}\n',
            stderr="",
        )

        result = HttpxWrapper().run("https://example.com")

    assert result.success is True
    assert result.parsed_data == [
        {"url": "https://example.com", "status_code": 200},
    ]
    run.assert_called_once()
