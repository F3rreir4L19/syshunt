from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from tools.base import ToolOptions, ToolWrapper


class NucleiWrapper(ToolWrapper):
    name = "nuclei"

    def build_command(self, target: str, options: ToolOptions) -> Sequence[str]:
        return [
            "nuclei",
            "-silent",
            "-jsonl",
            "-target",
            target,
            *options.extra_args,
        ]

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        for line in raw_output.splitlines():
            cleaned = line.strip()
            if not cleaned:
                continue

            try:
                parsed = json.loads(cleaned)
            except json.JSONDecodeError:
                findings.append({"raw": cleaned})
                continue

            if isinstance(parsed, dict):
                findings.append(parsed)

        return findings
