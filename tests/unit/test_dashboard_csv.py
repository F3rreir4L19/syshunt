"""Tests for dashboard CSV import helpers."""

from dashboard.app import _parse_domains_from_csv


def test_parse_csv_with_domain_column() -> None:
    csv_content = b"domain,notes\nexample.com,main\ntest.io,secondary\n"

    domains = _parse_domains_from_csv(csv_content)

    assert domains == ["example.com", "test.io"]


def test_parse_csv_plain_list() -> None:
    content = b"example.com\napi.test.io\n\n"

    domains = _parse_domains_from_csv(content)

    assert "example.com" in domains
    assert "api.test.io" in domains


def test_parse_csv_with_header_domain_case_insensitive() -> None:
    csv_content = b"Domain,Status\nexample.com,active\n"

    domains = _parse_domains_from_csv(csv_content)

    assert domains == ["example.com"]


def test_parse_csv_ignores_empty_lines() -> None:
    content = b"example.com\n\n\nother.io\n"

    domains = _parse_domains_from_csv(content)

    assert len(domains) == 2


def test_parse_csv_returns_empty_on_empty_file() -> None:
    assert _parse_domains_from_csv(b"") == []
