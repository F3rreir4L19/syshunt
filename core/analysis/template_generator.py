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


def _slugify(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text[:60].strip("-") or "generated"


def generate_nuclei_template(description: str, provider: AIProvider) -> Path:
    """Generate a nuclei template YAML from *description* and save it to disk.

    Returns the path to the saved file.

    Raises ValueError if the AI response is not a valid nuclei template structure.
    """
    prompt = _PROMPT.format(description=description.strip())
    raw = provider.complete(prompt).strip()

    # Strip markdown code fences if the model wraps the output
    if raw.startswith("```"):
        lines = raw.splitlines()
        raw = "\n".join(line for line in lines if not line.startswith("```")).strip()

    if not raw.startswith("id:"):
        raise ValueError(
            f"AI response is not a valid nuclei template (must start with 'id:'): {raw[:100]!r}"
        )
    if "info:" not in raw:
        raise ValueError(
            f"AI response missing 'info:' section: {raw[:200]!r}"
        )

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
