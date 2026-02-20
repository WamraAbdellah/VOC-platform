"""
Enrichment Worker
=================
Worker autonome qui écoute Redis et enrichit les CVE en temps réel.
"""
import asyncio
import json
import os
import redis
import httpx
from loguru import logger

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
DATABASE_URL = os.getenv("DATABASE_URL")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

r = redis.from_url(REDIS_URL, decode_responses=True)


async def enrich_cve(cve_id: str) -> dict:
    """Enrichit une CVE depuis NVD + EPSS + CISA KEV"""
    result = {"cve_id": cve_id}
    
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    async with httpx.AsyncClient(timeout=20) as client:
        # NVD
        try:
            resp = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
                headers=headers,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("vulnerabilities"):
                    vuln = data["vulnerabilities"][0]["cve"]
                    metrics = vuln.get("metrics", {})
                    
                    score = None
                    if "cvssMetricV31" in metrics:
                        score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV30" in metrics:
                        score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                    
                    result["cvss_score"] = score
                    descriptions = vuln.get("descriptions", [])
                    result["description"] = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
        except Exception as e:
            logger.warning(f"NVD error for {cve_id}: {e}")

        # EPSS
        try:
            resp = await client.get(f"https://api.first.org/data/v1/epss?cve={cve_id}", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("data"):
                    result["epss_score"] = float(data["data"][0]["epss"])
                    result["epss_percentile"] = float(data["data"][0]["percentile"])
        except Exception as e:
            logger.warning(f"EPSS error for {cve_id}: {e}")

    logger.info(f"✅ Enriched {cve_id}: CVSS={result.get('cvss_score')}, EPSS={result.get('epss_score')}")
    return result


def main():
    """Boucle principale - écoute la queue Redis enrichment:queue"""
    logger.info("🚀 Enrichment Worker démarré, écoute enrichment:queue...")
    
    while True:
        try:
            # Blpop bloque jusqu'à recevoir un message
            message = r.blpop("enrichment:queue", timeout=30)
            
            if message:
                _, payload = message
                data = json.loads(payload)
                cve_id = data.get("cve_id")
                
                if cve_id:
                    logger.info(f"📨 Reçu: {cve_id}")
                    result = asyncio.run(enrich_cve(cve_id))
                    
                    # Publier le résultat
                    r.set(f"enriched:{cve_id}", json.dumps(result), ex=86400)
                    r.publish("enrichment:results", json.dumps(result))
        
        except Exception as e:
            logger.error(f"Worker error: {e}")
            asyncio.sleep(5)


if __name__ == "__main__":
    main()
