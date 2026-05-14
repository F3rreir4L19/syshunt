"""Unit tests for FfufWrapper — no real ffuf binary needed."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from tools.base import ToolOptions
from tools.ffuf_wrapper import FfufWrapper


def _completed(stdout: str, returncode: int = 0) -> MagicMock:
    m = MagicMock()
    m.stdout = stdout
    m.stderr = ""
    m.returncode = returncode
    return m


def _ffuf_output(results: list[dict]) -> str:
    return json.dumps({"results": results})


class TestFfufWrapperBuildCommand:
    def test_includes_fuzz_url(self) -> None:
        cmd = FfufWrapper().build_command("https://example.com", ToolOptions())
        assert any("FUZZ" in str(c) for c in cmd)

    def test_adds_default_wordlist_when_none_given(self) -> None:
        cmd = FfufWrapper().build_command("https://example.com", ToolOptions())
        assert "-w" in cmd

    def test_respects_custom_wordlist_in_extra_args(self) -> None:
        options = ToolOptions(extra_args=["-w", "/custom/wordlist.txt"])
        cmd = FfufWrapper().build_command("https://example.com", options)
        # Should not duplicate -w
        assert cmd.count("-w") == 1
        assert "/custom/wordlist.txt" in cmd

    def test_strips_trailing_slash(self) -> None:
        cmd = FfufWrapper().build_command("https://example.com/", ToolOptions())
        assert "https://example.com/FUZZ" in cmd


class TestFfufWrapperParseOutput:
    def test_parses_results(self) -> None:
        raw = _ffuf_output([
            {"url": "https://example.com/admin", "status": 200, "length": 1234,
             "words": 10, "lines": 5, "input": {"FUZZ": "admin"}},
        ])
        results = FfufWrapper().parse_output(raw)
        assert len(results) == 1
        assert results[0]["url"] == "https://example.com/admin"
        assert results[0]["status"] == 200
        assert results[0]["input"] == "admin"

    def test_empty_results(self) -> None:
        raw = _ffuf_output([])
        assert FfufWrapper().parse_output(raw) == []

    def test_invalid_json(self) -> None:
        assert FfufWrapper().parse_output("not json") == []

    def test_empty_output(self) -> None:
        assert FfufWrapper().parse_output("") == []


class TestFfufWrapperRun:
    def test_successful_run(self) -> None:
        raw = _ffuf_output([
            {"url": "https://example.com/admin", "status": 200, "length": 100,
             "words": 5, "lines": 2, "input": {"FUZZ": "admin"}},
        ])
        with patch("subprocess.run", return_value=_completed(raw)):
            result = FfufWrapper().run("https://example.com")
        assert result.success is True
        assert len(result.parsed_data) == 1

    def test_binary_not_found(self) -> None:
        with patch("subprocess.run", side_effect=FileNotFoundError("ffuf")):
            result = FfufWrapper().run("https://example.com")
        assert result.success is False
        assert "not found" in (result.error or "").lower()

    def test_nonzero_returncode(self) -> None:
        with patch("subprocess.run", return_value=_completed("", returncode=1)):
            result = FfufWrapper().run("https://example.com")
        assert result.success is False
