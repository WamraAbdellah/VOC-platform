"""API - Enrichissement CVE"""
from fastapi import APIRouter
from app.services.cve_enrichment import enrichment_service

router = APIRouter()

@router.get("/cve/{cve_id}")
async def enrich_cve(cve_id: str):
    """Enrichit et retourne les détails complets d'une CVE depuis toutes les APIs"""
    data = await enrichment_service.enrich_cve(cve_id)
    return data

@router.get("/kev")
async def get_kev_stats():
    """Retourne les statistiques de la liste CISA KEV"""
    kev = await enrichment_service.get_full_kev_list()
    return {
        "total": len(kev),
        "recent": kev[:10] if kev else [],
    }
