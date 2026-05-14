from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from tools.base import ToolOptions, ToolWrapper


class FfufWrapper(ToolWrapper):
    """Directory and parameter fuzzing with ffuf.

    *target* must be a URL base (e.g. ``https://example.com``).
    The wordlist path must be provided via ``ToolOptions.extra_args`` or via
    the ``wordlist`` attribute of a subclass.  If ``extra_args`` contains
    ``-w <path>`` it is forwarded directly; otherwise the wrapper adds
    ``-w /usr/share/wordlists/dirb/common.txt`` as a default.
    """

    name = "ffuf"
    default_wordlist: str = "/usr/share/wordlists/dirb/common.txt"

    def build_command(self, target: str, options: ToolOptions) -> Sequence[str]:
        base_url = target.rstrip("/")
        cmd: list[str] = [
            "ffuf",
            "-u", f"{base_url}/FUZZ",
            "-of", "json",
            "-o", "-",
            "-silent",
        ]
        if not any(a == "-w" for a in options.extra_args):
            cmd += ["-w", self.default_wordlist]
        cmd += list(options.extra_args)
        return cmd

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse ffuf JSON output into a list of result records."""
        stripped = raw_output.strip()
        if not stripped:
            return []
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            return []
        results = data.get("results", [])
        parsed: list[dict[str, Any]] = []
        for r in results:
            parsed.append({
                "url": r.get("url", ""),
                "status": r.get("status", 0),
                "length": r.get("length", 0),
                "words": r.get("words", 0),
                "lines": r.get("lines", 0),
                "input": r.get("input", {}).get("FUZZ", ""),
            })
        return parsed
