from datetime import timedelta

from threatfeed.celery_app import app


def test_beat_schedule_targets_both_feeds() -> None:
    schedule = app.conf.beat_schedule

    assert set(schedule) == {"urlhaus", "threatfox", "phishtank"}
    assert schedule["urlhaus"]["args"] == ("urlhaus",)
    assert isinstance(schedule["urlhaus"]["schedule"], timedelta)
    assert schedule["threatfox"]["args"] == ("threatfox",)
    assert schedule["phishtank"]["args"] == ("phishtank",)
    assert isinstance(schedule["phishtank"]["schedule"], timedelta)


def test_celery_delivery_settings() -> None:
    assert app.conf.timezone == "UTC"
    assert app.conf.task_acks_late is True
    assert app.conf.task_ignore_result is True
    assert app.conf.worker_prefetch_multiplier == 1
    assert app.conf.broker_transport_options["visibility_timeout"] == 7200


def test_ingest_task_is_registered() -> None:
    import threatfeed.tasks  # noqa: F401  # registers the task on the app

    assert "threatfeed.ingest_feed" in app.tasks
