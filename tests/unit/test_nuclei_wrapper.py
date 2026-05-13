from subprocess import CompletedProcess
from unittest.mock import patch

from tools.base import ToolOptions
from tools.nuclei_wrapper import NucleiWrapper


def test_nuclei_builds_expected_command() -> None:
    command = NucleiWrapper().build_command(
        "https://example.com",
        ToolOptions(extra_args=["-severity", "high,critical"]),
    )

    assert command == [
        "nuclei",
        "-silent",
        "-jsonl",
        "-target",
        "https://example.com",
        "-severity",
        "high,critical",
    ]


def test_nuclei_parses_json_lines_and_keeps_unparsed_evidence() -> None:
    output = (
        '{"template-id":"exposure","matched-at":"https://example.com"}\n'
        "[info] skipped malformed template\n"
    )

    parsed = NucleiWrapper().parse_output(output)

    assert parsed == [
        {"template-id": "exposure", "matched-at": "https://example.com"},
        {"raw": "[info] skipped malformed template"},
    ]


def test_nuclei_run_uses_mocked_subprocess() -> None:
    with patch("tools.base.subprocess.run") as run:
        run.return_value = CompletedProcess(
            args=["nuclei"],
            returncode=0,
            stdout='{"template-id":"exposure","matched-at":"https://example.com"}\n',
            stderr="",
        )

        result = NucleiWrapper().run("https://example.com")

    assert result.success is True
    assert result.parsed_data == [
        {"template-id": "exposure", "matched-at": "https://example.com"},
    ]
    run.assert_called_once()
