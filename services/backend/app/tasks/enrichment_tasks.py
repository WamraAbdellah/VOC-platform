"""
Celery Tasks - Enrichissement des vulnérabilités
"""
import asyncio
from loguru import logger
from app.celery_app import celery_app


@celery_app.task(name="app.tasks.enrichment_tasks.enrich_single_cve", bind=True, max_retries=3)
def enrich_single_cve(self, cve_id: str, vulnerability_id: str):
    """
    Enrichit une CVE unique depuis les APIs gratuites.
    Déclenché à chaque nouvelle vulnérabilité détectée.
    """
    from app.services.cve_enrichment import enrichment_service
    from app.services.voc_scoring import scoring_engine, VulnerabilityContext, EnvironmentType
    from sqlalchemy import create_engine, text
    from app.config import settings
    
    try:
        # Utilise asyncio.run car Celery est synchrone
        enriched = asyncio.run(enrichment_service.enrich_cve(cve_id))
        
        engine = create_engine(settings.DATABASE_URL)
        with engine.connect() as conn:
            # Upsert dans le cache CVE
            conn.execute(text("""
                INSERT INTO cve_cache (
                    cve_id, description, cvss_v3_score, cvss_v2_score, cvss_v3_vector,
                    severity, epss_score, epss_percentile, is_in_kev,
                    exploit_available, exploit_maturity, cwe_ids
                ) VALUES (
                    :cve_id, :description, :cvss_v3_score, :cvss_v2_score, :cvss_v3_vector,
                    :severity, :epss_score, :epss_percentile, :is_in_kev,
                    :exploit_available, :exploit_maturity, :cwe_ids::jsonb
                )
                ON CONFLICT (cve_id) DO UPDATE SET
                    epss_score = EXCLUDED.epss_score,
                    epss_percentile = EXCLUDED.epss_percentile,
                    is_in_kev = EXCLUDED.is_in_kev,
                    exploit_available = EXCLUDED.exploit_available,
                    exploit_maturity = EXCLUDED.exploit_maturity,
                    cached_at = NOW()
            """), {
                "cve_id": cve_id,
                "description": enriched.get("description"),
                "cvss_v3_score": enriched.get("cvss_v3_score"),
                "cvss_v2_score": enriched.get("cvss_v2_score"),
                "cvss_v3_vector": enriched.get("cvss_v3_vector"),
                "severity": enriched.get("severity", "MEDIUM"),
                "epss_score": enriched.get("epss_score"),
                "epss_percentile": enriched.get("epss_percentile"),
                "is_in_kev": enriched.get("is_in_kev", False),
                "exploit_available": enriched.get("exploit_available", False),
                "exploit_maturity": enriched.get("exploit_maturity"),
                "cwe_ids": "[]",
            })
            
            # Recalcul du score VOC avec les nouvelles données
            conn.execute(text("""
                UPDATE vulnerabilities v
                SET voc_score = (
                    SELECT 
                        LEAST(100, GREATEST(0,
                            (COALESCE(v.cvss_score, 5) / 10.0 * 25) +
                            (CASE WHEN a.is_internet_exposed THEN 25 ELSE 5 END) +
                            (a.business_criticality * 4) +
                            (CASE WHEN c.is_in_kev THEN 30 
                                  WHEN c.exploit_available THEN 15
                                  ELSE COALESCE(c.epss_score * 20, 0) END) +
                            (CASE WHEN a.environment = 'PRODUCTION' THEN 10 
                                  WHEN a.environment = 'STAGING' THEN 6
                                  ELSE 3 END)
                        ))
                    FROM assets a
                    LEFT JOIN cve_cache c ON v.cve_id = c.cve_id
                    WHERE a.id = v.asset_id
                ),
                updated_at = NOW()
                WHERE v.id = :vuln_id
            """), {"vuln_id": vulnerability_id})
            
            conn.commit()
        
        logger.info(f"✅ CVE {cve_id} enrichie avec succès")
        return {"cve_id": cve_id, "status": "enriched"}
        
    except Exception as exc:
        logger.error(f"Erreur enrichissement {cve_id}: {exc}")
        raise self.retry(exc=exc, countdown=60 * (self.request.retries + 1))


@celery_app.task(name="app.tasks.enrichment_tasks.sync_cisa_kev")
def sync_cisa_kev():
    """
    Synchronisation quotidienne de la liste CISA KEV.
    Met à jour is_in_kev pour toutes les CVE en cache.
    """
    from app.services.cve_enrichment import enrichment_service
    from sqlalchemy import create_engine, text
    from app.config import settings
    
    logger.info("📡 Synchronisation CISA KEV...")
    
    kev_list = asyncio.run(enrichment_service.get_full_kev_list())
    kev_cve_ids = {v["cveID"] for v in kev_list}
    
    engine = create_engine(settings.DATABASE_URL)
    with engine.connect() as conn:
        # Reset tous les flags KEV
        conn.execute(text("UPDATE cve_cache SET is_in_kev = FALSE"))
        
        # Set ceux qui sont dans la KEV
        for cve_id in kev_cve_ids:
            conn.execute(
                text("UPDATE cve_cache SET is_in_kev = TRUE WHERE cve_id = :cve_id"),
                {"cve_id": cve_id}
            )
        
        # Marque les vulnérabilités liées comme critiques
        conn.execute(text("""
            UPDATE vulnerabilities v
            SET severity = 'CRITICAL',
                voc_score = GREATEST(voc_score, 85),
                updated_at = NOW()
            FROM cve_cache c
            WHERE v.cve_id = c.cve_id AND c.is_in_kev = TRUE
              AND v.status NOT IN ('RESOLVED', 'ACCEPTED_RISK')
        """))
        
        conn.commit()
    
    logger.info(f"✅ CISA KEV sync: {len(kev_cve_ids)} CVEs marquées")
    return {"synced": len(kev_cve_ids)}


@celery_app.task(name="app.tasks.enrichment_tasks.sync_epss_scores")
def sync_epss_scores():
    """
    Mise à jour hebdomadaire des scores EPSS pour toutes les CVE en cache.
    """
    import httpx
    from sqlalchemy import create_engine, text
    from app.config import settings
    
    logger.info("📡 Synchronisation scores EPSS...")
    
    engine = create_engine(settings.DATABASE_URL)
    with engine.connect() as conn:
        result = conn.execute(text("SELECT cve_id FROM cve_cache"))
        cve_ids = [row[0] for row in result]
    
    if not cve_ids:
        return {"updated": 0}
    
    # EPSS API supporte jusqu'à 100 CVEs en batch
    updated = 0
    batch_size = 100
    
    with engine.connect() as conn:
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            cve_param = "&cve=".join(batch)
            
            try:
                resp = httpx.get(
                    f"https://api.first.org/data/v1/epss?cve={cve_param}",
                    timeout=30
                )
                data = resp.json()
                
                for entry in data.get("data", []):
                    conn.execute(text("""
                        UPDATE cve_cache 
                        SET epss_score = :epss, epss_percentile = :pct
                        WHERE cve_id = :cve_id
                    """), {
                        "epss": float(entry["epss"]),
                        "pct": float(entry["percentile"]),
                        "cve_id": entry["cve"],
                    })
                    updated += 1
                
            except Exception as e:
                logger.error(f"EPSS batch error: {e}")
        
        conn.commit()
    
    logger.info(f"✅ EPSS sync: {updated} scores mis à jour")
    return {"updated": updated}


@celery_app.task(name="app.tasks.enrichment_tasks.recalculate_all_voc_scores")
def recalculate_all_voc_scores():
    """Recalcule le score VOC pour toutes les vulnérabilités non résolues"""
    from sqlalchemy import create_engine, text
    from app.config import settings
    
    engine = create_engine(settings.DATABASE_URL)
    with engine.connect() as conn:
        conn.execute(text("""
            UPDATE vulnerabilities v
            SET voc_score = LEAST(100, GREATEST(0,
                    (COALESCE(v.cvss_score, 5) / 10.0 * 25) +
                    (CASE WHEN a.is_internet_exposed THEN 25 ELSE 5 END) +
                    (a.business_criticality * 4) +
                    (CASE WHEN c.is_in_kev THEN 30 
                          WHEN c.exploit_available THEN 15
                          ELSE COALESCE(c.epss_score * 20, 0) END) +
                    (CASE WHEN a.environment = 'PRODUCTION' THEN 10 
                          WHEN a.environment = 'STAGING' THEN 6
                          ELSE 3 END)
                )),
                severity = CASE 
                    WHEN voc_score >= 80 THEN 'CRITICAL'::severity_level
                    WHEN voc_score >= 60 THEN 'HIGH'::severity_level
                    WHEN voc_score >= 40 THEN 'MEDIUM'::severity_level
                    ELSE 'LOW'::severity_level
                END,
                updated_at = NOW()
            FROM assets a
            LEFT JOIN cve_cache c ON v.cve_id = c.cve_id
            WHERE a.id = v.asset_id
              AND v.status NOT IN ('RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE')
        """))
        conn.commit()
    
    logger.info("✅ VOC scores recalculés")
    return {"status": "done"}
