"""
VOC Platform - FastAPI Backend
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from loguru import logger

from app.api import vulnerabilities, assets, scans, tickets, dashboard, auth, enrichment
from app.db.database import engine, Base
from app.celery_app import celery_app  # noqa

# ─── App ─────────────────────────────────────────────────
app = FastAPI(
    title="VOC Platform API",
    description="Vulnerability Operation Center - API de gestion des vulnérabilités",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# ─── CORS ────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:80"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Routes ──────────────────────────────────────────────
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["Vulnerabilities"])
app.include_router(assets.router, prefix="/api/assets", tags=["Assets"])
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(tickets.router, prefix="/api/tickets", tags=["Tickets"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard & KPIs"])
app.include_router(enrichment.router, prefix="/api/enrichment", tags=["Enrichment"])

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "voc-backend"}

@app.on_event("startup")
async def startup():
    logger.info("🚀 VOC Backend starting up...")
    # Créer les tables si elles n'existent pas
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ Database ready")
