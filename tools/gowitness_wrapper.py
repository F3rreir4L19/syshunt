from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from tools.base import ToolOptions, ToolWrapper


class GoWitnessWrapper(ToolWrapper):
    """Wrapper for gowitness screenshot tool.

    options.output_path must be set to the directory where screenshots will
    be saved.  The pipeline task passes OUTPUT_DIR/screenshots/{target_id}/.
    parse_output returns the list of status lines emitted by gowitness so the
    pipeline task can log them; the actual file paths are derived from the
    output directory listing after the run.
    """

    name = "gowitness"

    def build_command(self, target: str, options: ToolOptions) -> Sequence[str]:
        screenshot_path = str(options.screenshot_dir or Path("screenshots"))
        return [
            "gowitness",
            "single",
            "--url", target,
            "--screenshot-path", screenshot_path,
            *options.extra_args,
        ]

    def parse_output(self, raw_output: str) -> list[str]:
        """Return non-empty lines from gowitness stdout (status messages)."""
        return [line.strip() for line in raw_output.splitlines() if line.strip()]
