"""
Celery Tasks - Notifications & Alertes VOC
"""
from loguru import logger
from app.celery_app import celery_app


@celery_app.task(name="app.tasks.notification_tasks.alert_critical_unresolved")
def alert_critical_unresolved():
    """
    Alerte toutes les heures si des vulnérabilités CRITICAL ne sont pas traitées
    depuis plus de 24h.
    """
    from sqlalchemy import create_engine, text
    from app.config import settings
    
    engine = create_engine(settings.DATABASE_URL)
    with engine.connect() as conn:
        # Vulnérabilités critiques non assignées depuis 24h
        critical_vulns = conn.execute(text("""
            SELECT v.id, v.title, v.cve_id, v.voc_score, a.name as asset_name,
                   EXTRACT(EPOCH FROM (NOW() - v.first_detected)) / 3600 as hours_open
            FROM vulnerabilities v
            LEFT JOIN assets a ON v.asset_id = a.id
            WHERE v.severity = 'CRITICAL'
              AND v.status = 'NEW'
              AND v.first_detected < NOW() - INTERVAL '24 hours'
              AND v.is_false_positive = FALSE
            ORDER BY v.voc_score DESC
            LIMIT 20
        """)).mappings().all()
        
        if not critical_vulns:
            return {"alerts_sent": 0}
        
        # Créer des notifications dans la base
        for vuln in critical_vulns:
            # Vérifier si une notif récente existe déjà
            existing = conn.execute(text("""
                SELECT id FROM notifications
                WHERE related_resource_id = :vuln_id::uuid
                  AND created_at > NOW() - INTERVAL '4 hours'
                  AND type = 'critical'
            """), {"vuln_id": str(vuln["id"])}).fetchone()
            
            if not existing:
                conn.execute(text("""
                    INSERT INTO notifications (title, message, type, related_resource_type, related_resource_id)
                    VALUES (:title, :message, 'critical', 'vulnerability', :vuln_id::uuid)
                """), {
                    "title": f"⚠️ CRITICAL non traité: {vuln['cve_id'] or vuln['title']}",
                    "message": (
                        f"Asset: {vuln['asset_name']} | "
                        f"VOC Score: {vuln['voc_score']} | "
                        f"Ouvert depuis {int(vuln['hours_open'])}h"
                    ),
                    "vuln_id": str(vuln["id"]),
                })
        
        conn.commit()
        logger.info(f"🔔 {len(critical_vulns)} alertes CRITICAL générées")
    
    return {"alerts_sent": len(critical_vulns)}
