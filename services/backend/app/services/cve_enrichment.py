"""
CVE Enrichment Service
======================
Interroge les APIs gratuites pour enrichir les CVE :
- NVD (NIST) : détails CVE, CVSS
- CISA KEV   : vulnérabilités activement exploitées
- EPSS       : probabilité d'exploitation
- GreyNoise  : exploitation observée sur internet
- OSV.dev    : vulnérabilités open-source
- ExploitDB  : disponibilité des exploits (via CVE Circl)
"""
import asyncio
import json
from typing import Optional
import httpx
from loguru import logger
from app.config import settings


NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
GREYNOISE_URL = "https://api.greynoise.io/v3/community"
OSV_URL = "https://api.osv.dev/v1/query"
CVE_CIRCL_URL = "https://cve.circl.lu/api/cve"


class CVEEnrichmentService:
    """Service d'enrichissement des CVE depuis les APIs gratuites"""

    def __init__(self):
        self.headers = {}
        if settings.NVD_API_KEY:
            self.headers["apiKey"] = settings.NVD_API_KEY
        
        self._kev_cache: set = set()
        self._kev_loaded = False

    async def enrich_cve(self, cve_id: str) -> dict:
        """
        Enrichissement complet d'une CVE.
        Retourne toutes les données consolidées.
        """
        logger.info(f"🔍 Enrichissement de {cve_id}")
        
        results = await asyncio.gather(
            self.get_nvd_details(cve_id),
            self.get_epss_score(cve_id),
            self.check_cisa_kev(cve_id),
            self.get_circl_details(cve_id),
            return_exceptions=True,
        )

        nvd_data, epss_data, is_kev, circl_data = results
        
        # Gestion des erreurs individuelles
        if isinstance(nvd_data, Exception):
            logger.warning(f"NVD failed for {cve_id}: {nvd_data}")
            nvd_data = {}
        if isinstance(epss_data, Exception):
            epss_data = {}
        if isinstance(is_kev, Exception):
            is_kev = False
        if isinstance(circl_data, Exception):
            circl_data = {}

        return {
            "cve_id": cve_id,
            **nvd_data,
            "epss_score": epss_data.get("epss"),
            "epss_percentile": epss_data.get("percentile"),
            "is_in_kev": is_kev,
            "exploit_available": circl_data.get("exploit_available", False),
            "exploit_maturity": circl_data.get("exploit_maturity"),
        }

    async def get_nvd_details(self, cve_id: str) -> dict:
        """Récupère les détails depuis NVD NIST (gratuit, ~50 req/30s avec clé)"""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                NVD_BASE_URL,
                params={"cveId": cve_id},
                headers=self.headers,
            )
            resp.raise_for_status()
            data = resp.json()

            if not data.get("vulnerabilities"):
                return {}

            vuln = data["vulnerabilities"][0]["cve"]
            
            # CVSS v3 prioritaire
            cvss_v3 = None
            cvss_v2 = None
            
            metrics = vuln.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_v3 = cvss_data["baseScore"]
                cvss_vector = cvss_data["vectorString"]
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_v3 = cvss_data["baseScore"]
                cvss_vector = cvss_data["vectorString"]
            
            if "cvssMetricV2" in metrics:
                cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            # Description en anglais
            descriptions = vuln.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"), ""
            )

            # CWEs
            weaknesses = vuln.get("weaknesses", [])
            cwe_ids = []
            for w in weaknesses:
                for desc in w.get("description", []):
                    if desc["value"].startswith("CWE-"):
                        cwe_ids.append(desc["value"])

            return {
                "description": description,
                "cvss_v3_score": cvss_v3,
                "cvss_v2_score": cvss_v2,
                "cvss_v3_vector": cvss_vector if cvss_v3 else None,
                "severity": self._cvss_to_severity(cvss_v3 or cvss_v2 or 0),
                "cwe_ids": cwe_ids,
                "published_date": vuln.get("published"),
                "last_modified_date": vuln.get("lastModified"),
                "raw_nvd_data": vuln,
            }

    async def get_epss_score(self, cve_id: str) -> dict:
        """
        EPSS = Exploit Prediction Scoring System
        Probabilité qu'une CVE soit exploitée dans les 30 prochains jours.
        API gratuite de FIRST.org
        """
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(EPSS_URL, params={"cve": cve_id})
            resp.raise_for_status()
            data = resp.json()
            
            if data.get("data"):
                entry = data["data"][0]
                return {
                    "epss": float(entry["epss"]),
                    "percentile": float(entry["percentile"]),
                }
            return {}

    async def check_cisa_kev(self, cve_id: str) -> bool:
        """
        Vérifie si la CVE est dans la liste CISA KEV
        (Known Exploited Vulnerabilities - preuve d'exploitation réelle)
        API gratuite
        """
        if not self._kev_loaded:
            await self._load_kev_list()
        
        return cve_id in self._kev_cache

    async def _load_kev_list(self):
        """Charge la liste complète CISA KEV"""
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(CISA_KEV_URL)
                resp.raise_for_status()
                data = resp.json()
                
                self._kev_cache = {
                    v["cveID"] for v in data.get("vulnerabilities", [])
                }
                self._kev_loaded = True
                logger.info(f"✅ CISA KEV chargée: {len(self._kev_cache)} CVEs")
        except Exception as e:
            logger.error(f"Erreur chargement CISA KEV: {e}")

    async def get_full_kev_list(self) -> list:
        """Retourne la liste complète CISA KEV avec métadonnées"""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
            return data.get("vulnerabilities", [])

    async def get_circl_details(self, cve_id: str) -> dict:
        """
        CVE Circl Luxembourg - API gratuite enrichissant les CVE
        avec infos sur les exploits disponibles
        """
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{CVE_CIRCL_URL}/{cve_id}")
            if resp.status_code == 404:
                return {}
            resp.raise_for_status()
            data = resp.json()
            
            # Détection d'exploit via refmap
            refmap = data.get("refmap", {})
            exploit_available = "exploit-db" in refmap or "metasploit" in refmap
            
            exploit_maturity = None
            if "metasploit" in refmap:
                exploit_maturity = "FUNCTIONAL"
            elif "exploit-db" in refmap:
                exploit_maturity = "POC"

            return {
                "exploit_available": exploit_available,
                "exploit_maturity": exploit_maturity,
            }

    async def check_greynoise(self, ip: str) -> dict:
        """
        GreyNoise Community API (gratuit, 1000 req/jour)
        Vérifie si une IP est connue pour scanner/exploiter des vulnérabilités
        """
        if not settings.GREYNOISE_API_KEY:
            return {}
        
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{GREYNOISE_URL}/{ip}",
                headers={"key": settings.GREYNOISE_API_KEY},
            )
            if resp.status_code == 404:
                return {"noise": False, "riot": False}
            resp.raise_for_status()
            data = resp.json()
            return {
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "classification": data.get("classification"),
                "name": data.get("name"),
            }

    def _cvss_to_severity(self, score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "INFO"


# Singleton
enrichment_service = CVEEnrichmentService()
