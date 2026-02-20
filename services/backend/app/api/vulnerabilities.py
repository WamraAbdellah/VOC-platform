"""
API - Gestion des vulnérabilités
"""
from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from pydantic import BaseModel
from datetime import datetime

from app.db.database import get_db
from app.services.voc_scoring import scoring_engine, VulnerabilityContext, EnvironmentType
from app.services.cve_enrichment import enrichment_service

router = APIRouter()


# ─── Pydantic Schemas ─────────────────────────────────────
class VulnerabilityCreate(BaseModel):
    asset_id: UUID
    title: str
    cve_id: Optional[str] = None
    description: Optional[str] = None
    cvss_score: float
    affected_component: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    is_internet_exposed: bool = False
    business_criticality: int = 3
    environment: str = "PRODUCTION"


class VulnerabilityUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[UUID] = None
    remediation_advice: Optional[str] = None
    remediation_deadline: Optional[datetime] = None
    is_false_positive: Optional[bool] = None
    false_positive_reason: Optional[str] = None
    risk_accepted: Optional[bool] = None
    risk_accepted_reason: Optional[str] = None


class VulnerabilityFilter(BaseModel):
    severity: Optional[list[str]] = None
    status: Optional[list[str]] = None
    asset_id: Optional[UUID] = None
    is_in_kev: Optional[bool] = None
    min_voc_score: Optional[float] = None


# ─── Routes ───────────────────────────────────────────────
@router.get("/")
async def list_vulnerabilities(
    page: int = Query(1, ge=1),
    size: int = Query(25, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    sort_by: str = Query("voc_score", enum=["voc_score", "cvss_score", "first_detected", "severity"]),
    order: str = Query("desc", enum=["asc", "desc"]),
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Liste des vulnérabilités avec pagination, filtres et tri.
    Par défaut triées par VOC Score (priorisation contextualisée).
    """
    # Construction requête SQL dynamique
    query = "SELECT * FROM vulnerabilities WHERE is_false_positive = FALSE"
    params = {}

    if severity:
        query += " AND severity = :severity"
        params["severity"] = severity.upper()
    
    if status:
        query += " AND status = :status"
        params["status"] = status.upper()
    
    if search:
        query += " AND (title ILIKE :search OR cve_id ILIKE :search)"
        params["search"] = f"%{search}%"

    order_dir = "DESC" if order == "desc" else "ASC"
    query += f" ORDER BY {sort_by} {order_dir}"
    query += f" LIMIT :limit OFFSET :offset"
    params["limit"] = size
    params["offset"] = (page - 1) * size

    from sqlalchemy import text
    result = await db.execute(text(query), params)
    vulns = result.mappings().all()

    # Count total
    count_q = "SELECT COUNT(*) FROM vulnerabilities WHERE is_false_positive = FALSE"
    count_result = await db.execute(text(count_q))
    total = count_result.scalar()

    return {
        "items": [dict(v) for v in vulns],
        "total": total,
        "page": page,
        "size": size,
        "pages": (total + size - 1) // size,
    }


@router.get("/{vuln_id}")
async def get_vulnerability(vuln_id: UUID, db: AsyncSession = Depends(get_db)):
    """Détail d'une vulnérabilité avec son score VOC détaillé"""
    from sqlalchemy import text
    result = await db.execute(
        text("SELECT * FROM vulnerabilities WHERE id = :id"),
        {"id": str(vuln_id)}
    )
    vuln = result.mappings().first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return dict(vuln)


@router.post("/")
async def create_vulnerability(
    data: VulnerabilityCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Crée une vulnérabilité et calcule son score VOC automatiquement"""
    
    # Calcul du score VOC
    ctx = VulnerabilityContext(
        cvss_score=data.cvss_score,
        cve_id=data.cve_id,
        is_internet_exposed=data.is_internet_exposed,
        business_criticality=data.business_criticality,
        environment=EnvironmentType(data.environment),
    )
    
    # Si CVE connue, on enrichit en background
    if data.cve_id:
        background_tasks.add_task(enrich_vulnerability_background, data.cve_id, db)
    
    score_result = scoring_engine.calculate(ctx)

    from sqlalchemy import text
    import uuid
    
    vuln_id = str(uuid.uuid4())
    severity = score_result["severity"]
    
    await db.execute(
        text("""
            INSERT INTO vulnerabilities 
            (id, asset_id, cve_id, title, description, cvss_score, severity,
             affected_component, port, protocol, voc_score, status,
             exposure_score, business_impact_score, exploitability_score, environment_factor)
            VALUES 
            (:id, :asset_id, :cve_id, :title, :description, :cvss_score, :severity,
             :affected_component, :port, :protocol, :voc_score, 'NEW',
             :exposure_score, :business_score, :exploitability_score, :environment_factor)
        """),
        {
            "id": vuln_id,
            "asset_id": str(data.asset_id),
            "cve_id": data.cve_id,
            "title": data.title,
            "description": data.description,
            "cvss_score": data.cvss_score,
            "severity": severity,
            "affected_component": data.affected_component,
            "port": data.port,
            "protocol": data.protocol,
            "voc_score": score_result["voc_score"],
            "exposure_score": score_result["components"]["exposure_score"],
            "business_score": score_result["components"]["business_score"],
            "exploitability_score": score_result["components"]["exploitability_score"],
            "environment_factor": score_result["components"]["environment_factor"],
        }
    )
    
    return {
        "id": vuln_id,
        "voc_score_details": score_result,
        "message": "Vulnerability created and scored",
    }


@router.patch("/{vuln_id}")
async def update_vulnerability(
    vuln_id: UUID,
    data: VulnerabilityUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Met à jour le statut, assignation ou remédiation d'une vulnérabilité"""
    from sqlalchemy import text
    
    updates = {k: v for k, v in data.dict().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No data to update")
    
    if "status" in updates and updates["status"] == "RESOLVED":
        updates["resolved_at"] = datetime.utcnow()
    
    set_clause = ", ".join([f"{k} = :{k}" for k in updates.keys()])
    updates["id"] = str(vuln_id)
    updates["updated_at"] = datetime.utcnow()
    
    await db.execute(
        text(f"UPDATE vulnerabilities SET {set_clause}, updated_at = :updated_at WHERE id = :id"),
        updates
    )
    return {"message": "Updated successfully"}


@router.post("/{vuln_id}/score")
async def recalculate_score(vuln_id: UUID, db: AsyncSession = Depends(get_db)):
    """Recalcule le score VOC d'une vulnérabilité (après enrichissement)"""
    from sqlalchemy import text
    
    result = await db.execute(
        text("""
            SELECT v.*, a.business_criticality, a.is_internet_exposed, a.environment,
                   c.epss_score, c.is_in_kev, c.exploit_available, c.exploit_maturity
            FROM vulnerabilities v
            LEFT JOIN assets a ON v.asset_id = a.id
            LEFT JOIN cve_cache c ON v.cve_id = c.cve_id
            WHERE v.id = :id
        """),
        {"id": str(vuln_id)}
    )
    row = result.mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")

    ctx = VulnerabilityContext(
        cvss_score=row["cvss_score"] or 0,
        is_internet_exposed=row["is_internet_exposed"] or False,
        business_criticality=row["business_criticality"] or 3,
        environment=EnvironmentType(row["environment"] or "PRODUCTION"),
        epss_score=row["epss_score"],
        is_in_kev=row["is_in_kev"] or False,
        exploit_available=row["exploit_available"] or False,
        exploit_maturity=row["exploit_maturity"],
    )
    
    score_result = scoring_engine.calculate(ctx)
    
    await db.execute(
        text("""
            UPDATE vulnerabilities SET 
                voc_score = :voc_score,
                severity = :severity,
                updated_at = NOW()
            WHERE id = :id
        """),
        {
            "voc_score": score_result["voc_score"],
            "severity": score_result["severity"],
            "id": str(vuln_id),
        }
    )
    
    return score_result


async def enrich_vulnerability_background(cve_id: str, db: AsyncSession):
    """Tâche background d'enrichissement d'une CVE"""
    try:
        data = await enrichment_service.enrich_cve(cve_id)
        from sqlalchemy import text
        await db.execute(
            text("""
                INSERT INTO cve_cache (cve_id, description, cvss_v3_score, cvss_v2_score, 
                    cvss_v3_vector, severity, epss_score, epss_percentile, is_in_kev,
                    exploit_available, exploit_maturity, cwe_ids)
                VALUES (:cve_id, :description, :cvss_v3_score, :cvss_v2_score,
                    :cvss_v3_vector, :severity, :epss_score, :epss_percentile, :is_in_kev,
                    :exploit_available, :exploit_maturity, :cwe_ids)
                ON CONFLICT (cve_id) DO UPDATE SET
                    epss_score = EXCLUDED.epss_score,
                    is_in_kev = EXCLUDED.is_in_kev,
                    exploit_available = EXCLUDED.exploit_available,
                    cached_at = NOW()
            """),
            {
                "cve_id": cve_id,
                "description": data.get("description"),
                "cvss_v3_score": data.get("cvss_v3_score"),
                "cvss_v2_score": data.get("cvss_v2_score"),
                "cvss_v3_vector": data.get("cvss_v3_vector"),
                "severity": data.get("severity", "MEDIUM"),
                "epss_score": data.get("epss_score"),
                "epss_percentile": data.get("epss_percentile"),
                "is_in_kev": data.get("is_in_kev", False),
                "exploit_available": data.get("exploit_available", False),
                "exploit_maturity": data.get("exploit_maturity"),
                "cwe_ids": json.dumps(data.get("cwe_ids", [])),
            }
        )
        await db.commit()
        logger.info(f"✅ CVE {cve_id} enrichie avec succès")
    except Exception as e:
        logger.error(f"Erreur enrichissement {cve_id}: {e}")


import json
from loguru import logger
