"""
Celery - Configuration des tâches asynchrones VOC
"""
from celery import Celery
from celery.schedules import crontab
from app.config import settings

celery_app = Celery(
    "voc_tasks",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.tasks.scan_tasks",
        "app.tasks.enrichment_tasks",
        "app.tasks.kpi_tasks",
        "app.tasks.notification_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="Europe/Paris",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)

# ─── Tâches planifiées ───────────────────────────────────
celery_app.conf.beat_schedule = {
    # Enrichissement KEV quotidien (CISA Known Exploited Vulnerabilities)
    "sync-kev-daily": {
        "task": "app.tasks.enrichment_tasks.sync_cisa_kev",
        "schedule": crontab(hour=6, minute=0),
    },
    # Snapshot KPI quotidien
    "kpi-snapshot-daily": {
        "task": "app.tasks.kpi_tasks.take_kpi_snapshot",
        "schedule": crontab(hour=7, minute=0),
    },
    # Enrichissement EPSS hebdomadaire
    "sync-epss-weekly": {
        "task": "app.tasks.enrichment_tasks.sync_epss_scores",
        "schedule": crontab(day_of_week=1, hour=3, minute=0),
    },
    # Alertes vulnérabilités critiques non traitées (chaque heure)
    "alert-critical-unresolved": {
        "task": "app.tasks.notification_tasks.alert_critical_unresolved",
        "schedule": crontab(minute=0),
    },
    # Re-calcul VOC score (toutes les 6h)
    "recalculate-voc-scores": {
        "task": "app.tasks.enrichment_tasks.recalculate_all_voc_scores",
        "schedule": crontab(hour="*/6"),
    },
}
