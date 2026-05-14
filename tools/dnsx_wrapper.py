from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from tools.base import ToolOptions, ToolResult, ToolWrapper


class DnsxWrapper(ToolWrapper):
    """Resolve and validate a list of subdomains using dnsx.

    Accepts a newline-separated list of subdomains as the *target* string
    (or a single subdomain) and returns those that resolve successfully,
    filtering out NXDOMAIN and wildcard responses.
    """

    name = "dnsx"

    def build_command(self, target: str, options: ToolOptions) -> Sequence[str]:
        return [
            "dnsx",
            "-silent",
            "-json",
            "-l", "-",   # read list from stdin (caller must pipe; handled by run override)
            *options.extra_args,
        ]

    def run(self, target: str, options: ToolOptions | None = None) -> ToolResult:
        """Run dnsx with *target* as a newline-separated subdomain list on stdin."""
        import subprocess

        tool_options = options or ToolOptions()
        cmd = [
            "dnsx",
            "-silent",
            "-json",
            *tool_options.extra_args,
        ]

        try:
            completed = subprocess.run(
                cmd,
                input=target,
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

    def parse_output(self, raw_output: str) -> list[str]:
        """Return list of resolved hostnames from dnsx JSON-lines output."""
        resolved: list[str] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = record.get("host", "")
            if host:
                resolved.append(host.lower())
        return sorted(set(resolved))
