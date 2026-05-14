"""Tests for core/analysis/template_generator.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core.analysis.template_generator import generate_nuclei_template


_VALID_YAML = """\
id: exposed-admin-panel
info:
  name: Exposed Admin Panel
  severity: high
  description: Admin panel accessible without authentication.

requests:
  - method: GET
    path:
      - /admin
    matchers:
      - type: word
        words:
          - "Admin Panel"
"""

_INVALID_YAML_NO_ID = """\
info:
  name: Missing ID
  severity: medium
"""

_INVALID_YAML_NO_INFO = "id: no-info-template\nsome: stuff\n"


class TestGenerateNucleiTemplate:
    def test_saves_valid_template_to_disk(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(
            "core.analysis.template_generator._TEMPLATES_DIR", tmp_path / "generated"
        )
        provider = MagicMock()
        provider.complete.return_value = _VALID_YAML

        output = generate_nuclei_template("Exposed admin panel without authentication", provider)

        assert output.exists()
        assert output.suffix == ".yaml"
        assert output.read_text(encoding="utf-8") == _VALID_YAML.strip()

    def test_returns_path_to_saved_file(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(
            "core.analysis.template_generator._TEMPLATES_DIR", tmp_path / "generated"
        )
        provider = MagicMock()
        provider.complete.return_value = _VALID_YAML

        output = generate_nuclei_template("some vuln", provider)

        assert isinstance(output, Path)

    def test_raises_value_error_when_missing_id(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(
            "core.analysis.template_generator._TEMPLATES_DIR", tmp_path / "generated"
        )
        provider = MagicMock()
        provider.complete.return_value = _INVALID_YAML_NO_ID

        with pytest.raises(ValueError, match="must start with 'id:'"):
            generate_nuclei_template("missing id test", provider)

    def test_raises_value_error_when_missing_info(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(
            "core.analysis.template_generator._TEMPLATES_DIR", tmp_path / "generated"
        )
        provider = MagicMock()
        provider.complete.return_value = _INVALID_YAML_NO_INFO

        with pytest.raises(ValueError, match="missing 'info:'"):
            generate_nuclei_template("missing info test", provider)

    def test_strips_markdown_code_fences(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(
            "core.analysis.template_generator._TEMPLATES_DIR", tmp_path / "generated"
        )
        provider = MagicMock()
        provider.complete.return_value = f"```yaml\n{_VALID_YAML}\n```"

        output = generate_nuclei_template("test", provider)

        content = output.read_text(encoding="utf-8")
        assert "```" not in content
        assert content.startswith("id:")

    def test_avoids_overwriting_existing_file(self, tmp_path, monkeypatch) -> None:
        generated_dir = tmp_path / "generated"
        generated_dir.mkdir(parents=True)
        monkeypatch.setattr(
            "core.analysis.template_generator._TEMPLATES_DIR", generated_dir
        )
        provider = MagicMock()
        provider.complete.return_value = _VALID_YAML

        path1 = generate_nuclei_template("same description", provider)
        path2 = generate_nuclei_template("same description", provider)

        assert path1 != path2
        assert path1.exists()
        assert path2.exists()
