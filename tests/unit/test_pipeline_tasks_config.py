from core.pipeline.tasks import (
    DEFAULT_REDIS_URL,
    celery_app,
    get_redis_url,
    should_run_tasks_eagerly,
)


def test_get_redis_url_uses_default(monkeypatch) -> None:
    monkeypatch.delenv("REDIS_URL", raising=False)

    assert get_redis_url() == DEFAULT_REDIS_URL


def test_should_run_tasks_eagerly_reads_env(monkeypatch) -> None:
    monkeypatch.setenv("CELERY_TASK_ALWAYS_EAGER", "true")

    assert should_run_tasks_eagerly() is True


def test_celery_app_has_json_serialization() -> None:
    assert celery_app.conf.task_serializer == "json"
    assert celery_app.conf.result_serializer == "json"
    assert celery_app.conf.accept_content == ["json"]
