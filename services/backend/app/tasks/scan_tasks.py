"""Celery Tasks - Scan orchestration"""
from loguru import logger
from app.celery_app import celery_app


@celery_app.task(name="app.tasks.scan_tasks.run_scan", bind=True)
def run_scan(self, scan_id: str, target: str, scan_type: str, options: dict):
    """
    Lance un scan et ingère les résultats en base.
    """
    import asyncio
    from sqlalchemy import create_engine, text
    from app.config import settings
    
    engine = create_engine(settings.DATABASE_URL)
    
    # Marquer comme RUNNING
    with engine.connect() as conn:
        conn.execute(text("""
            UPDATE scans SET status = 'RUNNING', started_at = NOW() WHERE id = :id
        """), {"id": scan_id})
        conn.commit()
    
    try:
        from services.scanner.scanner import scan_orchestrator
        results = asyncio.run(scan_orchestrator.run_infrastructure_scan(target, options))
        
        # Ingestion des résultats
        vuln_count = _ingest_scan_results(engine, scan_id, results)
        
        with engine.connect() as conn:
            conn.execute(text("""
                UPDATE scans SET 
                    status = 'COMPLETED', 
                    completed_at = NOW(),
                    vulnerabilities_found = :count
                WHERE id = :id
            """), {"count": vuln_count, "id": scan_id})
            conn.commit()
        
        logger.info(f"✅ Scan {scan_id} terminé: {vuln_count} vulnérabilités")
        return {"scan_id": scan_id, "vulnerabilities_found": vuln_count}
        
    except Exception as exc:
        logger.error(f"Scan {scan_id} failed: {exc}")
        with engine.connect() as conn:
            conn.execute(text("""
                UPDATE scans SET status = 'FAILED', error_message = :err WHERE id = :id
            """), {"err": str(exc), "id": scan_id})
            conn.commit()
        raise


def _ingest_scan_results(engine, scan_id: str, results: dict) -> int:
    """Ingère les résultats de scan en vulnérabilités"""
    import uuid, json
    from sqlalchemy import text
    
    count = 0
    
    with engine.connect() as conn:
        # Récupérer org_id depuis le scan
        scan = conn.execute(text("SELECT org_id, target FROM scans WHERE id = :id"), 
                           {"id": scan_id}).fetchone()
        if not scan:
            return 0
        
        org_id, target = scan
        
        # Ingérer les findings Nuclei
        for nuclei_result in results.get("nuclei", []):
            for finding in nuclei_result.get("findings", []):
                vuln_id = str(uuid.uuid4())
                cve_ids = finding.get("cve", [])
                cve_id = cve_ids[0] if cve_ids else None
                
                cvss = finding.get("cvss_score") or 5.0
                severity_map = {"critical": "CRITICAL", "high": "HIGH", 
                               "medium": "MEDIUM", "low": "LOW", "info": "INFO"}
                severity = severity_map.get(finding.get("severity", "").lower(), "MEDIUM")
                
                conn.execute(text("""
                    INSERT INTO vulnerabilities 
                        (id, org_id, scan_id, cve_id, title, description, 
                         cvss_score, severity, voc_score, affected_component)
                    VALUES 
                        (:id, :org_id, :scan_id, :cve_id, :title, :desc,
                         :cvss, :severity::severity_level, :voc, :component)
                    ON CONFLICT DO NOTHING
                """), {
                    "id": vuln_id, "org_id": str(org_id), "scan_id": scan_id,
                    "cve_id": cve_id, "title": finding.get("name", "Unknown"),
                    "desc": finding.get("description"),
                    "cvss": cvss,
                    "severity": severity,
                    "voc": cvss * 10,  # Score initial basique, sera recalculé
                    "component": finding.get("matched_at"),
                })
                
                # Déclencher enrichissement si CVE connue
                if cve_id:
                    from app.tasks.enrichment_tasks import enrich_single_cve
                    enrich_single_cve.delay(cve_id, vuln_id)
                
                count += 1
        
        conn.commit()
    
    return count
