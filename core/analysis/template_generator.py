"""Generate nuclei YAML templates from natural language descriptions via an AI provider."""

from __future__ import annotations

import re
from pathlib import Path

from core.analysis.provider import AIProvider

_TEMPLATES_DIR = Path(__file__).parent / "templates" / "generated"

_PROMPT = """\
Generate a valid nuclei template YAML for the following vulnerability description.
The template must start with `id:` and include an `info:` section with name, severity,
and description. Return ONLY the YAML — no markdown, no code fences, no explanation.

Vulnerability description:
{description}"""

_REQUIRED_HTTP_KEYS = {"requests", "http", "network"}


def _slugify(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text[:60].strip("-") or "generated"


def _validate_nuclei_yaml(parsed: object) -> None:
    """Validate that *parsed* is a well-formed nuclei template dict.

    Raises ValueError with a descriptive message if any required field is missing
    or has an invalid type.
    """
    if not isinstance(parsed, dict):
        raise ValueError(f"Invalid nuclei template: root must be a YAML mapping, got {type(parsed).__name__}")

    template_id = parsed.get("id")
    if not template_id or not isinstance(template_id, str) or not template_id.strip():
        raise ValueError("Invalid nuclei template: 'id' must be a non-empty string")

    info = parsed.get("info")
    if not isinstance(info, dict):
        raise ValueError("Invalid nuclei template: 'info' must be a mapping")

    info_name = info.get("name")
    if not info_name or not isinstance(info_name, str) or not str(info_name).strip():
        raise ValueError("Invalid nuclei template: 'info.name' must be a non-empty string")

    info_severity = info.get("severity")
    if not info_severity or not isinstance(info_severity, str) or not str(info_severity).strip():
        raise ValueError("Invalid nuclei template: 'info.severity' must be a non-empty string")

    if not any(k in parsed for k in _REQUIRED_HTTP_KEYS):
        raise ValueError(
            f"Invalid nuclei template: must contain at least one of {sorted(_REQUIRED_HTTP_KEYS)}"
        )


def generate_nuclei_template(description: str, provider: AIProvider) -> Path:
    """Generate a nuclei template YAML from *description* and save it to disk.

    Returns the path to the saved file.

    Raises ValueError if the AI response is not a valid nuclei template structure.
    """
    import yaml

    prompt = _PROMPT.format(description=description.strip())
    raw = provider.complete(prompt).strip()

    # Strip markdown code fences if the model wraps the output
    if raw.startswith("```"):
        lines = raw.splitlines()
        raw = "\n".join(line for line in lines if not line.startswith("```")).strip()

    # Parse and validate the YAML before saving
    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid nuclei template: YAML parse error: {exc}") from exc

    _validate_nuclei_yaml(parsed)

    _TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
    slug = _slugify(description)
    output_path = _TEMPLATES_DIR / f"{slug}.yaml"

    # Avoid silent overwrites by appending a counter when a file already exists
    counter = 0
    while output_path.exists():
        counter += 1
        output_path = _TEMPLATES_DIR / f"{slug}-{counter}.yaml"

    output_path.write_text(raw, encoding="utf-8")
    return output_path
