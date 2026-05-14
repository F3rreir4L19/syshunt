from __future__ import annotations

from collections.abc import Sequence

from tools.base import ToolOptions, ToolWrapper


class AmassWrapper(ToolWrapper):
    name = "amass"

    def build_command(self, target: str, options: ToolOptions) -> Sequence[str]:
        return [
            "amass",
            "enum",
            "-passive",
            "-d",
            target,
            *options.extra_args,
        ]

    def parse_output(self, raw_output: str) -> list[str]:
        return sorted(
            {
                line.strip().lower()
                for line in raw_output.splitlines()
                if line.strip()
            }
        )
