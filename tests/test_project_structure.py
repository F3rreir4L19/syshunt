from pathlib import Path


def test_phase_one_project_directories_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    expected_directories = [
        "core/recon",
        "core/analysis/templates/custom",
        "core/analysis/templates/generated",
        "core/monitor",
        "core/pipeline",
        "core/db/migrations",
        "dashboard/pages",
        "dashboard/components",
        "tools",
    ]

    missing = [path for path in expected_directories if not (root / path).is_dir()]

    assert missing == []
