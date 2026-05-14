from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ToolResult:
    success: bool
    raw_stdout: str
    raw_stderr: str
    parsed_data: Any
    error: str | None = None
    # raw_output is kept for backward compatibility; always equals raw_stdout
    raw_output: str = field(default="", init=False, repr=False)

    def __post_init__(self) -> None:
        self.raw_output = self.raw_stdout


@dataclass(slots=True)
class ToolOptions:
    timeout: int = 120
    output_path: Path | None = None
    extra_args: list[str] = field(default_factory=list)
    # screenshot_dir is used by GoWitnessWrapper as the --screenshot-path argument;
    # output_path remains the audit-log file path used by the base class.
    screenshot_dir: Path | None = None


class ToolWrapper(ABC):
    name: str

    def run(self, target: str, options: ToolOptions | None = None) -> ToolResult:
        tool_options = options or ToolOptions()
        command = self.build_command(target, tool_options)

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                check=False,
                text=True,
                timeout=tool_options.timeout,
            )
        except FileNotFoundError as exc:
            return ToolResult(
                success=False,
                raw_stdout="",
                raw_stderr="",
                parsed_data=[],
                error=f"{self.name} executable not found: {exc}",
            )
        except subprocess.TimeoutExpired as exc:
            raw_stdout = exc.stdout or ""
            raw_stderr = exc.stderr or ""
            self._write_output(raw_stdout, tool_options.output_path)
            return ToolResult(
                success=False,
                raw_stdout=raw_stdout,
                raw_stderr=raw_stderr,
                parsed_data=[],
                error=f"{self.name} timed out after {tool_options.timeout}s",
            )

        raw_stdout = completed.stdout or ""
        raw_stderr = completed.stderr or ""
        self._write_output(raw_stdout, tool_options.output_path)

        if completed.returncode != 0:
            return ToolResult(
                success=False,
                raw_stdout=raw_stdout,
                raw_stderr=raw_stderr,
                parsed_data=[],
                error=f"{self.name} exited with code {completed.returncode}",
            )

        return ToolResult(
            success=True,
            raw_stdout=raw_stdout,
            raw_stderr=raw_stderr,
            parsed_data=self.parse_output(raw_stdout),
            error=None,
        )

    @abstractmethod
    def build_command(self, target: str, options: ToolOptions) -> Sequence[str]:
        raise NotImplementedError

    @abstractmethod
    def parse_output(self, raw_output: str) -> Any:
        raise NotImplementedError

    @staticmethod
    def _write_output(raw_output: str, output_path: Path | None) -> None:
        if output_path is None:
            return

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(raw_output, encoding="utf-8")
