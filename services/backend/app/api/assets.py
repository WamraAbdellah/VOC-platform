"""API - Assets"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from pydantic import BaseModel
from typing import Optional
from app.db.database import get_db
import uuid

router = APIRouter()

class AssetCreate(BaseModel):
    name: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    asset_type: str = "SERVER"
    environment: str = "PRODUCTION"
    business_criticality: int = 3
    is_internet_exposed: bool = False
    tags: list = []

@router.get("/")
async def list_assets(db: AsyncSession = Depends(get_db)):
    result = await db.execute(text("""
        SELECT a.*, 
               COUNT(v.id) as vuln_count,
               COUNT(v.id) FILTER (WHERE v.severity = 'CRITICAL') as critical_count
        FROM assets a
        LEFT JOIN vulnerabilities v ON a.id = v.asset_id 
            AND v.status NOT IN ('RESOLVED', 'FALSE_POSITIVE')
        GROUP BY a.id ORDER BY a.created_at DESC
    """))
    return [dict(r) for r in result.mappings().all()]

@router.post("/")
async def create_asset(data: AssetCreate, db: AsyncSession = Depends(get_db)):
    asset_id = str(uuid.uuid4())
    org_result = await db.execute(text("SELECT id FROM organizations LIMIT 1"))
    org_id = str(org_result.scalar())
    
    await db.execute(text("""
        INSERT INTO assets (id, org_id, name, ip_address, hostname, asset_type, 
                            environment, business_criticality, is_internet_exposed, tags)
        VALUES (:id, :org_id, :name, :ip::inet, :hostname, :asset_type::asset_type,
                :environment::environment_type, :criticality, :exposed, :tags::jsonb)
    """), {
        "id": asset_id, "org_id": org_id, "name": data.name,
        "ip": data.ip_address, "hostname": data.hostname,
        "asset_type": data.asset_type, "environment": data.environment,
        "criticality": data.business_criticality, "exposed": data.is_internet_exposed,
        "tags": str(data.tags),
    })
    return {"id": asset_id, "message": "Asset created"}

@router.delete("/{asset_id}")
async def delete_asset(asset_id: str, db: AsyncSession = Depends(get_db)):
    await db.execute(text("DELETE FROM assets WHERE id = :id"), {"id": asset_id})
    return {"message": "Deleted"}
