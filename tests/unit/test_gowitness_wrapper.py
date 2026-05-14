from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from tools.base import ToolOptions
from tools.gowitness_wrapper import GoWitnessWrapper


def test_gowitness_builds_expected_command(tmp_path: Path) -> None:
    command = GoWitnessWrapper().build_command(
        "https://example.com", ToolOptions(screenshot_dir=tmp_path)
    )

    assert command == [
        "gowitness", "single",
        "--url", "https://example.com",
        "--screenshot-path", str(tmp_path),
    ]


def test_gowitness_defaults_screenshot_path_when_none() -> None:
    command = GoWitnessWrapper().build_command("https://example.com", ToolOptions())

    assert "--screenshot-path" in command
    idx = list(command).index("--screenshot-path")
    assert command[idx + 1] == "screenshots"


def test_gowitness_builds_command_with_extra_args(tmp_path: Path) -> None:
    command = GoWitnessWrapper().build_command(
        "https://example.com",
        ToolOptions(screenshot_dir=tmp_path, extra_args=["--no-http"]),
    )

    assert "--no-http" in command


def test_gowitness_parse_output_returns_nonempty_lines() -> None:
    output = "✔ 200 - https://example.com\n\n✗ timeout https://slow.example.com\n"

    parsed = GoWitnessWrapper().parse_output(output)

    assert parsed == [
        "✔ 200 - https://example.com",
        "✗ timeout https://slow.example.com",
    ]


def test_gowitness_run_uses_mocked_subprocess() -> None:
    with patch("tools.base.subprocess.run") as run:
        run.return_value = CompletedProcess(
            args=["gowitness"],
            returncode=0,
            stdout="✔ 200 - https://example.com\n",
            stderr="",
        )

        result = GoWitnessWrapper().run("https://example.com")

    assert result.success is True
    assert result.parsed_data == ["✔ 200 - https://example.com"]
    run.assert_called_once()


def test_gowitness_run_returns_failure_on_nonzero_exit() -> None:
    with patch("tools.base.subprocess.run") as run:
        run.return_value = CompletedProcess(
            args=["gowitness"], returncode=1, stdout="", stderr="error"
        )

        result = GoWitnessWrapper().run("https://example.com")

    assert result.success is False
