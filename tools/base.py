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
    raw_output: str
    parsed_data: Any
    error: str | None = None


@dataclass(slots=True)
class ToolOptions:
    timeout: int = 120
    output_path: Path | None = None
    extra_args: list[str] = field(default_factory=list)


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
                raw_output="",
                parsed_data=[],
                error=f"{self.name} executable not found: {exc}",
            )
        except subprocess.TimeoutExpired as exc:
            raw_output = (exc.stdout or "") + (exc.stderr or "")
            self._write_output(raw_output, tool_options.output_path)
            return ToolResult(
                success=False,
                raw_output=raw_output,
                parsed_data=[],
                error=f"{self.name} timed out after {tool_options.timeout}s",
            )

        raw_output = completed.stdout
        if completed.stderr:
            raw_output = f"{raw_output}{completed.stderr}"
        self._write_output(raw_output, tool_options.output_path)

        if completed.returncode != 0:
            return ToolResult(
                success=False,
                raw_output=raw_output,
                parsed_data=[],
                error=f"{self.name} exited with code {completed.returncode}",
            )

        return ToolResult(
            success=True,
            raw_output=raw_output,
            parsed_data=self.parse_output(raw_output),
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
