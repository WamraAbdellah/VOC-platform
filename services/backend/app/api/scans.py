"""API - Scans"""
from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from pydantic import BaseModel
from typing import Optional
from app.db.database import get_db
import uuid

router = APIRouter()

class ScanCreate(BaseModel):
    target: str
    scan_type: str = "NMAP"
    options: dict = {}
    name: Optional[str] = None

@router.get("/")
async def list_scans(db: AsyncSession = Depends(get_db)):
    result = await db.execute(text("SELECT * FROM scans ORDER BY created_at DESC LIMIT 50"))
    return [dict(r) for r in result.mappings().all()]

@router.post("/")
async def launch_scan(data: ScanCreate, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    scan_id = str(uuid.uuid4())
    org_result = await db.execute(text("SELECT id FROM organizations LIMIT 1"))
    org_id = str(org_result.scalar())
    
    await db.execute(text("""
        INSERT INTO scans (id, org_id, name, scan_type, status, target, options)
        VALUES (:id, :org_id, :name, :scan_type::scan_type, 'PENDING', :target, :options::jsonb)
    """), {
        "id": scan_id, "org_id": org_id,
        "name": data.name or f"{data.scan_type} - {data.target}",
        "scan_type": data.scan_type, "target": data.target,
        "options": str(data.options),
    })
    
    # Lancer le scan en arrière-plan via Celery
    from app.tasks.scan_tasks import run_scan
    background_tasks.add_task(lambda: run_scan.delay(scan_id, data.target, data.scan_type, data.options))
    
    return {"id": scan_id, "status": "PENDING", "message": "Scan queued"}

@router.get("/{scan_id}")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(text("SELECT * FROM scans WHERE id = :id"), {"id": scan_id})
    scan = result.mappings().first()
    if not scan:
        from fastapi import HTTPException
        raise HTTPException(status_code=404)
    return dict(scan)
