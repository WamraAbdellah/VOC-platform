"""API - Tickets de remédiation"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from pydantic import BaseModel
from typing import Optional
from uuid import UUID
from app.db.database import get_db
import uuid

router = APIRouter()

class TicketCreate(BaseModel):
    vulnerability_id: UUID
    title: str
    description: Optional[str] = None
    priority: str = "MEDIUM"
    due_date: Optional[str] = None

@router.get("/")
async def list_tickets(db: AsyncSession = Depends(get_db)):
    result = await db.execute(text("""
        SELECT t.*, v.title as vuln_title, v.cve_id, v.severity
        FROM tickets t
        LEFT JOIN vulnerabilities v ON t.vulnerability_id = v.id
        ORDER BY t.created_at DESC
    """))
    return [dict(r) for r in result.mappings().all()]

@router.post("/")
async def create_ticket(data: TicketCreate, db: AsyncSession = Depends(get_db)):
    ticket_id = str(uuid.uuid4())
    org_result = await db.execute(text("SELECT id FROM organizations LIMIT 1"))
    org_id = str(org_result.scalar())
    
    await db.execute(text("""
        INSERT INTO tickets (id, org_id, vulnerability_id, title, description, priority)
        VALUES (:id, :org_id, :vuln_id, :title, :description, :priority)
    """), {
        "id": ticket_id, "org_id": org_id,
        "vuln_id": str(data.vulnerability_id),
        "title": data.title, "description": data.description,
        "priority": data.priority,
    })
    
    # Mettre à jour le statut de la vulnérabilité
    await db.execute(text("""
        UPDATE vulnerabilities SET status = 'IN_REMEDIATION', updated_at = NOW()
        WHERE id = :vuln_id AND status = 'NEW'
    """), {"vuln_id": str(data.vulnerability_id)})
    
    return {"id": ticket_id, "message": "Ticket created"}

@router.patch("/{ticket_id}/status")
async def update_ticket_status(ticket_id: str, status: str, db: AsyncSession = Depends(get_db)):
    await db.execute(text("""
        UPDATE tickets SET status = :status::ticket_status, updated_at = NOW()
        WHERE id = :id
    """), {"status": status, "id": ticket_id})
    return {"message": "Updated"}
