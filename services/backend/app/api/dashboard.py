"""
API - Dashboard & KPIs VOC
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.db.database import get_db

router = APIRouter()


@router.get("/summary")
async def get_dashboard_summary(db: AsyncSession = Depends(get_db)):
    """
    Résumé global pour le dashboard principal VOC.
    Retourne tous les KPIs principaux en un seul appel.
    """
    # Compteurs par sévérité
    counts = await db.execute(text("""
        SELECT 
            COUNT(*) as total,
            COUNT(*) FILTER (WHERE severity = 'CRITICAL') as critical,
            COUNT(*) FILTER (WHERE severity = 'HIGH') as high,
            COUNT(*) FILTER (WHERE severity = 'MEDIUM') as medium,
            COUNT(*) FILTER (WHERE severity = 'LOW') as low,
            COUNT(*) FILTER (WHERE status = 'NEW') as new_vulns,
            COUNT(*) FILTER (WHERE status = 'IN_REMEDIATION') as in_remediation,
            COUNT(*) FILTER (WHERE status = 'RESOLVED') as resolved,
            COUNT(*) FILTER (WHERE status = 'ACCEPTED_RISK') as accepted_risk
        FROM vulnerabilities 
        WHERE is_false_positive = FALSE
    """))
    summary = dict(counts.mappings().first())

    # MTTR par sévérité (jours)
    mttr = await db.execute(text("""
        SELECT severity,
               ROUND(AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected)) / 86400)::numeric, 1) as avg_days,
               COUNT(*) as count
        FROM vulnerabilities
        WHERE status = 'RESOLVED' AND resolved_at IS NOT NULL
        GROUP BY severity
        ORDER BY severity
    """))
    mttr_data = [dict(r) for r in mttr.mappings().all()]

    # Top 10 vulnérabilités par VOC Score (actions prioritaires)
    top_vulns = await db.execute(text("""
        SELECT v.id, v.title, v.cve_id, v.voc_score, v.severity, v.status,
               a.name as asset_name, a.ip_address, a.environment,
               c.is_in_kev, c.epss_score
        FROM vulnerabilities v
        LEFT JOIN assets a ON v.asset_id = a.id
        LEFT JOIN cve_cache c ON v.cve_id = c.cve_id
        WHERE v.status NOT IN ('RESOLVED', 'FALSE_POSITIVE')
          AND v.is_false_positive = FALSE
        ORDER BY v.voc_score DESC NULLS LAST
        LIMIT 10
    """))
    top_vulns_data = [dict(r) for r in top_vulns.mappings().all()]

    # KEV non patchées (critique CISA)
    kev_count = await db.execute(text("""
        SELECT COUNT(*) 
        FROM vulnerabilities v
        JOIN cve_cache c ON v.cve_id = c.cve_id
        WHERE c.is_in_kev = TRUE 
          AND v.status NOT IN ('RESOLVED', 'ACCEPTED_RISK')
    """))
    kev_unpatched = kev_count.scalar() or 0

    # Évolution sur 30 jours (pour le graphique)
    trend = await db.execute(text("""
        SELECT DATE(first_detected) as date,
               COUNT(*) as discovered,
               COUNT(*) FILTER (WHERE status = 'RESOLVED') as resolved
        FROM vulnerabilities
        WHERE first_detected >= NOW() - INTERVAL '30 days'
        GROUP BY DATE(first_detected)
        ORDER BY date
    """))
    trend_data = [dict(r) for r in trend.mappings().all()]

    # Assets les plus exposés
    top_assets = await db.execute(text("""
        SELECT a.id, a.name, a.ip_address, a.environment, a.business_criticality,
               COUNT(v.id) as vuln_count,
               COUNT(v.id) FILTER (WHERE v.severity IN ('CRITICAL', 'HIGH')) as critical_high,
               MAX(v.voc_score) as max_voc_score
        FROM assets a
        LEFT JOIN vulnerabilities v ON a.id = v.asset_id 
            AND v.status NOT IN ('RESOLVED', 'FALSE_POSITIVE')
        GROUP BY a.id, a.name, a.ip_address, a.environment, a.business_criticality
        HAVING COUNT(v.id) > 0
        ORDER BY max_voc_score DESC NULLS LAST
        LIMIT 5
    """))
    top_assets_data = [dict(r) for r in top_assets.mappings().all()]

    return {
        "summary": summary,
        "mttr_by_severity": mttr_data,
        "top_vulnerabilities": top_vulns_data,
        "kev_unpatched_count": kev_unpatched,
        "trend_30d": trend_data,
        "top_exposed_assets": top_assets_data,
    }


@router.get("/kpis")
async def get_kpis(db: AsyncSession = Depends(get_db)):
    """KPIs détaillés pour le reporting client"""
    
    # MTTR global
    mttr_result = await db.execute(text("""
        SELECT ROUND(AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected)) / 86400)::numeric, 1) as mttr_global
        FROM vulnerabilities
        WHERE status = 'RESOLVED' AND resolved_at IS NOT NULL
    """))
    mttr_global = mttr_result.scalar()

    # Taux de remédiation
    rate_result = await db.execute(text("""
        SELECT 
            COUNT(*) FILTER (WHERE status = 'RESOLVED') as resolved,
            COUNT(*) as total
        FROM vulnerabilities WHERE is_false_positive = FALSE
    """))
    rate_data = dict(rate_result.mappings().first())
    remediation_rate = (
        (rate_data["resolved"] / rate_data["total"] * 100)
        if rate_data["total"] > 0 else 0
    )

    # Backlog moyen (âge des vuln non résolues)
    backlog_result = await db.execute(text("""
        SELECT ROUND(AVG(EXTRACT(EPOCH FROM (NOW() - first_detected)) / 86400)::numeric, 1) as avg_age_days
        FROM vulnerabilities
        WHERE status NOT IN ('RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE')
    """))
    avg_backlog_age = backlog_result.scalar()

    return {
        "mttr_global_days": mttr_global,
        "remediation_rate_pct": round(remediation_rate, 1),
        "avg_backlog_age_days": avg_backlog_age,
        "total_resolved": rate_data["resolved"],
        "total_open": rate_data["total"] - rate_data["resolved"],
    }


@router.get("/risk-matrix")
async def get_risk_matrix(db: AsyncSession = Depends(get_db)):
    """
    Matrice de risque : Business Criticality × VOC Score
    Pour visualisation graphique
    """
    result = await db.execute(text("""
        SELECT 
            a.business_criticality,
            v.severity,
            COUNT(v.id) as count,
            AVG(v.voc_score) as avg_score
        FROM vulnerabilities v
        JOIN assets a ON v.asset_id = a.id
        WHERE v.status NOT IN ('RESOLVED', 'FALSE_POSITIVE')
          AND v.is_false_positive = FALSE
        GROUP BY a.business_criticality, v.severity
        ORDER BY a.business_criticality DESC, avg_score DESC
    """))
    
    return [dict(r) for r in result.mappings().all()]
