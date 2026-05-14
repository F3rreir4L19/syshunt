from __future__ import annotations

from collections.abc import Sequence

from tools.base import ToolOptions, ToolWrapper


class GauWrapper(ToolWrapper):
    name = "gau"

    def build_command(self, target: str, options: ToolOptions) -> Sequence[str]:
        return [
            "gau",
            "--threads", "5",
            target,
            *options.extra_args,
        ]

    def parse_output(self, raw_output: str) -> list[str]:
        return sorted(
            {
                line.strip()
                for line in raw_output.splitlines()
                if line.strip() and line.strip().startswith("http")
            }
        )
