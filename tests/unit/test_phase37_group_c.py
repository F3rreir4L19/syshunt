"""Tests for Phase 3.7 Group C — Uso real.

Covers:
  C1 — core/notifications.py: payload correct, failure never propagates
  C2 — run_ai_analysis integrates notifications
  C3 — export_findings_csv / export_findings_markdown include expected fields
  C4 — GoWitnessWrapper uses v3 scan single syntax; filename=None tolerated
  C5 — README.md exists, is UTF-8, documents expected content
"""
from __future__ import annotations

import csv
import io
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.db.base import Base
from core.db.models import Finding, Target
from core.db import queries
from core.notifications import (
    _get_flag,
    _get_webhook_url,
    _post_discord,
    notify_high_score_finding,
    notify_new_program,
    notify_pipeline_error,
    notify_recon_completed,
    notify_scope_changed,
)
from tools.base import ToolOptions
from tools.gowitness_wrapper import GoWitnessWrapper


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _add_target(sf: sessionmaker[Session], domain: str = "example.com") -> Target:
    with sf() as session:
        target = Target(domain=domain)
        session.add(target)
        session.commit()
        session.refresh(target)
        return target


def _add_finding(
    sf: sessionmaker[Session],
    target_id: int,
    score: int = 90,
    severity: str = "high",
) -> Finding:
    with sf() as session:
        f = Finding(
            target_id=target_id,
            title="Test Finding",
            type="exposed-panel",
            severity=severity,
            url="https://example.com/admin",
            auto_score=score,
            status="new",
        )
        session.add(f)
        session.commit()
        session.refresh(f)
        return f


# ---------------------------------------------------------------------------
# C1 — Notifications
# ---------------------------------------------------------------------------


class TestNotificationsPayload:
    def test_notify_recon_completed_posts_correct_payload(self) -> None:
        posted: list[tuple[str, str]] = []

        def fake_post(url: str, content: str) -> None:
            posted.append((url, content))

        target = MagicMock()
        target.domain = "example.com"

        session = MagicMock()
        with (
            patch("core.notifications._get_flag", return_value=True),
            patch("core.notifications._get_webhook_url", return_value="https://discord.example/webhook"),
            patch("core.notifications._post_discord", side_effect=fake_post),
        ):
            notify_recon_completed(target, {"findings": 7, "high_critical": 2}, session=session)

        assert len(posted) == 1
        url, content = posted[0]
        assert url == "https://discord.example/webhook"
        assert "example.com" in content
        assert "7" in content
        assert "2" in content
        assert "RECON" in content

    def test_notify_high_score_finding_posts_correct_payload(self) -> None:
        posted: list[tuple[str, str]] = []

        def fake_post(url: str, content: str) -> None:
            posted.append((url, content))

        target = MagicMock()
        target.domain = "api.example.com"
        finding = MagicMock()
        finding.auto_score = 87
        finding.severity = "high"
        finding.type = "exposed-panel"
        finding.url = "https://api.example.com/admin"

        with (
            patch("core.notifications._get_flag", return_value=True),
            patch("core.notifications._get_webhook_url", return_value="https://discord.example/webhook"),
            patch("core.notifications._post_discord", side_effect=fake_post),
        ):
            notify_high_score_finding(finding, target, session=None)

        assert len(posted) == 1
        url, content = posted[0]
        assert "87" in content
        assert "HIGH" in content
        assert "api.example.com" in content

    def test_notify_recon_completed_skipped_when_flag_false(self) -> None:
        posted: list[str] = []

        with (
            patch("core.notifications._get_flag", return_value=False),
            patch("core.notifications._post_discord", side_effect=lambda u, c: posted.append(c)),
        ):
            notify_recon_completed(MagicMock(), {}, session=None)

        assert len(posted) == 0

    def test_notify_recon_completed_skipped_when_no_webhook(self) -> None:
        posted: list[str] = []

        with (
            patch("core.notifications._get_flag", return_value=True),
            patch("core.notifications._get_webhook_url", return_value=None),
            patch("core.notifications._post_discord", side_effect=lambda u, c: posted.append(c)),
        ):
            notify_recon_completed(MagicMock(), {}, session=None)

        assert len(posted) == 0


class TestNotificationsNeverPropagate:
    def test_post_discord_does_not_raise_on_network_error(self) -> None:
        import urllib.request

        with patch.object(urllib.request, "urlopen", side_effect=OSError("connection refused")):
            _post_discord("https://discord.example/webhook", "test message")
            # No exception raised

    def test_notify_recon_completed_does_not_raise_on_internal_error(self) -> None:
        with patch("core.notifications._get_flag", side_effect=RuntimeError("boom")):
            notify_recon_completed(MagicMock(), {}, session=None)
            # No exception raised

    def test_notify_high_score_finding_does_not_raise_on_internal_error(self) -> None:
        with patch("core.notifications._get_flag", side_effect=RuntimeError("boom")):
            notify_high_score_finding(MagicMock(), MagicMock(), session=None)

    def test_notify_new_program_stub_does_not_raise(self) -> None:
        notify_new_program(MagicMock())

    def test_notify_scope_changed_stub_does_not_raise(self) -> None:
        notify_scope_changed(MagicMock(), ["add.example.com"], ["old.example.com"])

    def test_notify_pipeline_error_stub_does_not_raise(self) -> None:
        notify_pipeline_error(1, "run_nuclei_scan", "subprocess failed")

    def test_post_discord_does_not_raise_on_http_error(self) -> None:
        import urllib.error

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("404")):
            _post_discord("https://discord.example/webhook", "test message")


# ---------------------------------------------------------------------------
# C2 — run_ai_analysis integrates notifications
# ---------------------------------------------------------------------------


class TestRunAiAnalysisNotifications:
    def test_notify_recon_completed_called_after_analysis(self) -> None:
        sf = _session_factory()
        target = _add_target(sf)

        with sf() as session:
            f = Finding(
                target_id=target.id,
                title="Low score finding",
                type="info",
                severity="info",
                url="https://example.com/info",
                auto_score=10,
                status="new",
            )
            session.add(f)
            session.commit()

        from core.pipeline import tasks
        import core.notifications as notif_module

        notif_calls: list[str] = []

        def fake_notify_completed(t, stats, session=None) -> None:
            notif_calls.append("completed")

        # run_ai_analysis imports notify_recon_completed from core.notifications inside the task,
        # so we patch it at the source module.
        with (
            patch.object(tasks, "SessionLocal", sf),
            patch("core.analysis.classifier.classify_finding", MagicMock()),
            patch.object(notif_module, "notify_recon_completed", fake_notify_completed),
            patch.object(notif_module, "notify_high_score_finding", MagicMock()),
        ):
            tasks.run_ai_analysis(target.id)

        assert "completed" in notif_calls

    def test_high_score_finding_triggers_notification(self) -> None:
        sf = _session_factory()
        target = _add_target(sf)

        with sf() as session:
            f = Finding(
                target_id=target.id,
                title="Critical finding",
                type="cve",
                severity="critical",
                url="https://example.com/cve",
                auto_score=90,
                status="new",
            )
            session.add(f)
            session.commit()

        from core.pipeline import tasks
        import core.notifications as notif_module

        high_notif_calls: list[int] = []

        def fake_notify_high(f, t, session=None) -> None:
            high_notif_calls.append(f.auto_score or 0)

        with (
            patch.object(tasks, "SessionLocal", sf),
            patch("core.analysis.classifier.classify_finding", MagicMock()),
            patch.object(notif_module, "notify_high_score_finding", fake_notify_high),
            patch.object(notif_module, "notify_recon_completed", MagicMock()),
        ):
            tasks.run_ai_analysis(target.id)

        # Score is 90 >= 80, notification should fire
        assert len(high_notif_calls) > 0


# ---------------------------------------------------------------------------
# C3 — Export CSV / Markdown
# ---------------------------------------------------------------------------


class TestExportCSV:
    def test_csv_contains_expected_fields(self) -> None:
        sf = _session_factory()
        target = _add_target(sf)
        with sf() as session:
            session.add(Finding(
                target_id=target.id,
                title="SQL Injection",
                type="sqli",
                severity="high",
                url="https://example.com/api",
                auto_score=75,
                status="new",
                confidence="likely",
            ))
            session.commit()

        with sf() as session:
            csv_str = queries.export_findings_csv(session)

        reader = csv.DictReader(io.StringIO(csv_str))
        rows = list(reader)
        assert len(rows) == 1
        row = rows[0]
        assert "id" in row
        assert "target" in row
        assert "severity" in row
        assert "status" in row
        assert "title" in row
        assert "url" in row
        assert "confidence" in row
        assert "auto_score" in row
        assert "type" in row
        assert row["title"] == "SQL Injection"
        assert row["severity"] == "high"

    def test_csv_export_empty_returns_header_only(self) -> None:
        sf = _session_factory()
        with sf() as session:
            csv_str = queries.export_findings_csv(session)

        reader = csv.DictReader(io.StringIO(csv_str))
        rows = list(reader)
        assert rows == []
        assert reader.fieldnames is not None
        assert "id" in reader.fieldnames


class TestExportMarkdown:
    def test_markdown_contains_expected_fields(self) -> None:
        sf = _session_factory()
        target = _add_target(sf)
        with sf() as session:
            session.add(Finding(
                target_id=target.id,
                title="Open Redirect",
                type="redirect",
                severity="medium",
                url="https://example.com/redirect",
                auto_score=55,
                status="new",
                confidence="possible",
            ))
            session.commit()

        with sf() as session:
            md = queries.export_findings_markdown(session)

        assert "Open Redirect" in md
        assert "MEDIUM" in md
        assert "example.com" in md
        assert "55" in md
        assert "possible" in md
        assert "# Findings" in md

    def test_markdown_empty_returns_no_findings_message(self) -> None:
        sf = _session_factory()
        with sf() as session:
            md = queries.export_findings_markdown(session)

        assert "No findings" in md


# ---------------------------------------------------------------------------
# C4 — GoWitness v3 wrapper
# ---------------------------------------------------------------------------


class TestGoWitnessV3:
    def test_command_uses_scan_single_syntax(self, tmp_path: Path) -> None:
        command = GoWitnessWrapper().build_command(
            "https://example.com", ToolOptions(screenshot_dir=tmp_path)
        )
        assert list(command[:3]) == ["gowitness", "scan", "single"]

    def test_command_includes_url_and_screenshot_path(self, tmp_path: Path) -> None:
        command = list(GoWitnessWrapper().build_command(
            "https://example.com", ToolOptions(screenshot_dir=tmp_path)
        ))
        assert "--url" in command
        idx_url = command.index("--url")
        assert command[idx_url + 1] == "https://example.com"
        assert "--screenshot-path" in command
        idx_path = command.index("--screenshot-path")
        assert command[idx_path + 1] == str(tmp_path)

    def test_command_default_screenshot_path(self) -> None:
        command = list(GoWitnessWrapper().build_command(
            "https://example.com", ToolOptions()
        ))
        assert "--screenshot-path" in command
        idx = command.index("--screenshot-path")
        assert command[idx + 1] == "screenshots"

    def test_filename_none_does_not_affect_screenshot_paths(
        self, tmp_path: Path
    ) -> None:
        """Dashboard derives screenshots from filesystem, not from filename field.

        filename=None in a ReconResult is valid; get_target_screenshot_paths
        must still return files from disk without raising.
        """
        # Create a fake screenshot file in the expected directory
        target_id = 42
        shot_dir = tmp_path / "screenshots" / str(target_id)
        shot_dir.mkdir(parents=True)
        (shot_dir / "test.png").write_bytes(b"\x89PNG\r\n")

        paths = queries.get_target_screenshot_paths(target_id, str(tmp_path))
        assert len(paths) == 1
        assert paths[0].endswith("test.png")


# ---------------------------------------------------------------------------
# C5 — README
# ---------------------------------------------------------------------------


class TestReadme:
    def test_readme_exists_and_is_utf8(self) -> None:
        readme = Path(__file__).parents[2] / "README.md"
        assert readme.exists(), "README.md does not exist"
        content = readme.read_bytes()
        # Must decode as UTF-8 without error
        text = content.decode("utf-8")
        assert len(text) > 100

    def test_readme_has_no_bom(self) -> None:
        readme = Path(__file__).parents[2] / "README.md"
        data = readme.read_bytes()
        assert not data.startswith(b"\xef\xbb\xbf"), "README.md must not have a UTF-8 BOM"

    def test_readme_documents_make_commands(self) -> None:
        readme = Path(__file__).parents[2] / "README.md"
        text = readme.read_text(encoding="utf-8")
        for cmd in ["make up", "make migrate", "make worker", "make dashboard", "make up-all"]:
            assert cmd in text, f"README.md is missing: {cmd}"

    def test_readme_documents_vps_security_warnings(self) -> None:
        readme = Path(__file__).parents[2] / "README.md"
        text = readme.read_text(encoding="utf-8")
        assert "DASHBOARD_PASSWORD" in text
        assert "authorized" in text.lower() or "authorization" in text.lower()

    def test_readme_documents_local_mode(self) -> None:
        readme = Path(__file__).parents[2] / "README.md"
        text = readme.read_text(encoding="utf-8")
        assert "localhost:8501" in text or "local" in text.lower()
