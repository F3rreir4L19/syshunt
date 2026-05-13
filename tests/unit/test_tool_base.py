from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from tools.base import ToolOptions, ToolWrapper


class EchoWrapper(ToolWrapper):
    name = "echo-tool"

    def build_command(self, target: str, options: ToolOptions) -> list[str]:
        return ["echo-tool", target, *options.extra_args]

    def parse_output(self, raw_output: str) -> list[str]:
        return [line for line in raw_output.splitlines() if line]


def test_tool_wrapper_runs_command_and_parses_output(tmp_path: Path) -> None:
    output_path = tmp_path / "echo.txt"

    with patch("tools.base.subprocess.run") as run:
        run.return_value = CompletedProcess(
            args=["echo-tool", "example.com"],
            returncode=0,
            stdout="one\ntwo\n",
            stderr="",
        )

        result = EchoWrapper().run(
            "example.com",
            ToolOptions(timeout=10, output_path=output_path, extra_args=["--json"]),
        )

    assert result.success is True
    assert result.raw_output == "one\ntwo\n"
    assert result.parsed_data == ["one", "two"]
    assert result.error is None
    assert output_path.read_text(encoding="utf-8") == "one\ntwo\n"
    run.assert_called_once()
    assert run.call_args.args[0] == ["echo-tool", "example.com", "--json"]


def test_tool_wrapper_returns_error_on_nonzero_exit() -> None:
    with patch("tools.base.subprocess.run") as run:
        run.return_value = CompletedProcess(
            args=["echo-tool", "example.com"],
            returncode=2,
            stdout="",
            stderr="bad target",
        )

        result = EchoWrapper().run("example.com")

    assert result.success is False
    assert result.parsed_data == []
    assert result.raw_output == "bad target"
    assert result.error == "echo-tool exited with code 2"
