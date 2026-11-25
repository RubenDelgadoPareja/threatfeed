"""Celery application and Beat schedule."""

from datetime import timedelta

from celery import Celery
from celery.schedules import crontab

from threatfeed.config import get_settings

settings = get_settings()

app = Celery("threatfeed", broker=settings.redis_url, include=["threatfeed.tasks"])
app.conf.update(
    task_ignore_result=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    # A full ThreatFox run takes minutes; do not let Redis redeliver it mid-run.
    broker_transport_options={"visibility_timeout": 7200},
    timezone="UTC",
    enable_utc=True,
    beat_schedule={
        "urlhaus": {
            "task": "threatfeed.ingest_feed",
            "schedule": timedelta(minutes=settings.urlhaus_interval_minutes),
            "args": ("urlhaus",),
        },
        "threatfox": {
            "task": "threatfeed.ingest_feed",
            "schedule": crontab(
                hour=settings.threatfox_schedule_hour,
                minute=settings.threatfox_schedule_minute,
            ),
            "args": ("threatfox",),
        },
        "phishtank": {
            "task": "threatfeed.ingest_feed",
            "schedule": timedelta(hours=settings.phishtank_interval_hours),
            "args": ("phishtank",),
        },
    },
)
