from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from tools.base import ToolOptions, ToolWrapper


class HttpxWrapper(ToolWrapper):
    name = "httpx"

    def build_command(self, target: str, options: ToolOptions) -> Sequence[str]:
        return [
            "httpx",
            "-silent",
            "-json",
            "-title",
            "-tech-detect",
            "-status-code",
            "-u",
            target,
            *options.extra_args,
        ]

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        for line in raw_output.splitlines():
            cleaned = line.strip()
            if not cleaned:
                continue

            try:
                parsed = json.loads(cleaned)
            except json.JSONDecodeError:
                results.append({"url": cleaned})
                continue

            if isinstance(parsed, dict):
                results.append(parsed)

        return results
