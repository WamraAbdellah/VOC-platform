"""
Celery Tasks - KPI & Reporting
"""
from loguru import logger
from app.celery_app import celery_app


@celery_app.task(name="app.tasks.kpi_tasks.take_kpi_snapshot")
def take_kpi_snapshot():
    """
    Snapshot KPI quotidien - stocke les métriques pour l'historique.
    """
    from sqlalchemy import create_engine, text
    from app.config import settings
    from datetime import date
    
    engine = create_engine(settings.DATABASE_URL)
    with engine.connect() as conn:
        # Récupérer l'org par défaut
        org = conn.execute(text("SELECT id FROM organizations LIMIT 1")).fetchone()
        if not org:
            return
        org_id = org[0]
        
        # Calculer les KPIs
        stats = conn.execute(text("""
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE severity = 'CRITICAL') as critical,
                COUNT(*) FILTER (WHERE severity = 'HIGH') as high,
                COUNT(*) FILTER (WHERE severity = 'MEDIUM') as medium,
                COUNT(*) FILTER (WHERE severity = 'LOW') as low,
                COUNT(*) FILTER (WHERE status = 'RESOLVED') as resolved
            FROM vulnerabilities WHERE is_false_positive = FALSE
        """)).fetchone()
        
        mttr = conn.execute(text("""
            SELECT AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected)) / 86400)
            FROM vulnerabilities
            WHERE status = 'RESOLVED' AND resolved_at IS NOT NULL
        """)).scalar()
        
        kev_unpatched = conn.execute(text("""
            SELECT COUNT(*) FROM vulnerabilities v
            JOIN cve_cache c ON v.cve_id = c.cve_id
            WHERE c.is_in_kev = TRUE AND v.status NOT IN ('RESOLVED', 'ACCEPTED_RISK')
        """)).scalar() or 0
        
        backlog_age = conn.execute(text("""
            SELECT AVG(EXTRACT(EPOCH FROM (NOW() - first_detected)) / 86400)
            FROM vulnerabilities
            WHERE status NOT IN ('RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE')
        """)).scalar()
        
        # Insérer le snapshot
        conn.execute(text("""
            INSERT INTO kpi_snapshots (
                org_id, snapshot_date, total_vulnerabilities,
                critical_count, high_count, medium_count, low_count,
                resolved_count, mttr_days, kev_unpatched, backlog_age_avg
            ) VALUES (
                :org_id, :date, :total, :critical, :high, :medium, :low,
                :resolved, :mttr, :kev, :backlog
            )
            ON CONFLICT (org_id, snapshot_date) DO UPDATE SET
                total_vulnerabilities = EXCLUDED.total_vulnerabilities,
                critical_count = EXCLUDED.critical_count,
                mttr_days = EXCLUDED.mttr_days,
                kev_unpatched = EXCLUDED.kev_unpatched
        """), {
            "org_id": str(org_id),
            "date": date.today(),
            "total": stats[0] or 0,
            "critical": stats[1] or 0,
            "high": stats[2] or 0,
            "medium": stats[3] or 0,
            "low": stats[4] or 0,
            "resolved": stats[5] or 0,
            "mttr": mttr,
            "kev": kev_unpatched,
            "backlog": backlog_age,
        })
        conn.commit()
    
    logger.info("✅ KPI snapshot enregistré")
    return {"status": "done", "date": str(date.today())}
