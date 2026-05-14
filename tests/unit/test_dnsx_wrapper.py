"""Unit tests for DnsxWrapper — no real dnsx binary needed."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from tools.dnsx_wrapper import DnsxWrapper


def _completed(stdout: str, returncode: int = 0) -> MagicMock:
    m = MagicMock()
    m.stdout = stdout
    m.stderr = ""
    m.returncode = returncode
    return m


def _json_line(host: str) -> str:
    return json.dumps({"host": host, "resolver": ["1.1.1.1"]})


class TestDnsxWrapperParseOutput:
    def test_parses_valid_json_lines(self) -> None:
        raw = "\n".join([_json_line("api.example.com"), _json_line("mail.example.com")])
        result = DnsxWrapper().parse_output(raw)
        assert sorted(result) == ["api.example.com", "mail.example.com"]

    def test_deduplicates_and_lowercases(self) -> None:
        raw = "\n".join([_json_line("API.example.com"), _json_line("api.example.com")])
        result = DnsxWrapper().parse_output(raw)
        assert result == ["api.example.com"]

    def test_skips_malformed_lines(self) -> None:
        raw = "not-json\n" + _json_line("ok.example.com")
        result = DnsxWrapper().parse_output(raw)
        assert result == ["ok.example.com"]

    def test_empty_output_returns_empty_list(self) -> None:
        assert DnsxWrapper().parse_output("") == []

    def test_skips_entries_without_host(self) -> None:
        raw = json.dumps({"resolver": ["1.1.1.1"]})
        assert DnsxWrapper().parse_output(raw) == []


class TestDnsxWrapperRun:
    def test_successful_run(self) -> None:
        raw = _json_line("api.example.com")
        with patch("subprocess.run", return_value=_completed(raw)):
            result = DnsxWrapper().run("api.example.com\nmail.example.com")
        assert result.success is True
        assert "api.example.com" in result.parsed_data

    def test_binary_not_found(self) -> None:
        with patch("subprocess.run", side_effect=FileNotFoundError("dnsx")):
            result = DnsxWrapper().run("example.com")
        assert result.success is False
        assert "not found" in (result.error or "").lower()

    def test_nonzero_returncode(self) -> None:
        with patch("subprocess.run", return_value=_completed("", returncode=1)):
            result = DnsxWrapper().run("example.com")
        assert result.success is False

    def test_timeout(self) -> None:
        exc = subprocess.TimeoutExpired(cmd=["dnsx"], timeout=30)
        exc.stdout = ""
        exc.stderr = ""
        with patch("subprocess.run", side_effect=exc):
            result = DnsxWrapper().run("example.com")
        assert result.success is False
        assert "timed out" in (result.error or "")
