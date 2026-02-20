"""Scanner Service API"""
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from scanner import scan_orchestrator

app = FastAPI(title="VOC Scanner Service")

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "NMAP"
    options: dict = {}

@app.get("/health")
def health():
    return {"status": "ok", "service": "voc-scanner"}

@app.post("/scan/infrastructure")
async def scan_infrastructure(req: ScanRequest):
    results = await scan_orchestrator.run_infrastructure_scan(req.target, req.options)
    return results

@app.post("/scan/container")
async def scan_container(req: ScanRequest):
    results = await scan_orchestrator.run_container_scan(req.target)
    return results
