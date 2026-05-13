from dashboard import app


def test_dashboard_pages_are_declared() -> None:
    assert [
        app.PAGE_TARGETS,
        app.PAGE_FINDINGS,
        app.PAGE_PROGRAMS,
        app.PAGE_SETTINGS,
    ] == ["Targets", "Findings", "Programs", "Settings"]
