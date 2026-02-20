"""
Scanner Service
===============
Orchestration des outils de scan gratuits :
- Nmap    : découverte réseau & ports
- Nuclei  : vulnérabilités web (templates gratuits)
- Trivy   : containers & IaC
- Nikto   : web server vulnerabilities
"""
import asyncio
import json
import subprocess
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
from loguru import logger

SCAN_RESULTS_DIR = Path("/app/scan_results")
SCAN_RESULTS_DIR.mkdir(exist_ok=True)


class NmapScanner:
    """Wrapper Nmap pour la découverte réseau et détection de services"""
    
    async def scan(self, target: str, options: dict = {}) -> dict:
        """
        Lance un scan Nmap et retourne les ports/services ouverts.
        
        Options:
          - fast: scan rapide (-F)
          - vuln: détection vulnérabilités (--script vuln) [lent]
          - os: détection OS (-O)
        """
        scan_id = str(uuid.uuid4())[:8]
        output_file = SCAN_RESULTS_DIR / f"nmap_{scan_id}.xml"
        
        # Construction de la commande
        cmd = ["nmap", "-oX", str(output_file)]
        
        if options.get("fast"):
            cmd += ["-F"]  # Top 100 ports
        else:
            cmd += ["-p", "1-65535", "--open"]
        
        if options.get("service_detection", True):
            cmd += ["-sV", "--version-intensity", "5"]
        
        if options.get("os_detection"):
            cmd += ["-O"]
        
        if options.get("vuln_scripts"):
            cmd += ["--script", "vuln"]  # ⚠️ Très lent, à utiliser avec précaution
        
        # Timeout (défaut 5 min)
        cmd += ["--host-timeout", f"{options.get('timeout', 300)}s"]
        cmd.append(target)
        
        logger.info(f"🔍 Nmap scan: {' '.join(cmd)}")
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), 
                timeout=options.get("timeout", 300) + 60
            )
            
            if proc.returncode != 0:
                raise RuntimeError(f"Nmap failed: {stderr.decode()}")
            
            # Parser le résultat XML
            return self._parse_nmap_xml(str(output_file))
            
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError("Nmap scan timeout")

    def _parse_nmap_xml(self, xml_file: str) -> dict:
        """Parse le XML Nmap et retourne une structure exploitable"""
        hosts = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall("host"):
                host_data = {"ports": [], "os": None}
                
                # IP
                for addr in host.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        host_data["ip"] = addr.get("addr")
                    elif addr.get("addrtype") == "mac":
                        host_data["mac"] = addr.get("addr")
                
                # Hostname
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hostname = hostnames.find("hostname")
                    if hostname is not None:
                        host_data["hostname"] = hostname.get("name")
                
                # Ports ouverts
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            port_data = {
                                "port": int(port.get("portid")),
                                "protocol": port.get("protocol"),
                                "state": "open",
                            }
                            service = port.find("service")
                            if service is not None:
                                port_data["service"] = service.get("name")
                                port_data["product"] = service.get("product", "")
                                port_data["version"] = service.get("version", "")
                                port_data["extra_info"] = service.get("extrainfo", "")
                            
                            # Scripts NSE (vulnérabilités)
                            scripts = []
                            for script in port.findall("script"):
                                scripts.append({
                                    "id": script.get("id"),
                                    "output": script.get("output"),
                                })
                            if scripts:
                                port_data["scripts"] = scripts
                            
                            host_data["ports"].append(port_data)
                
                # OS Detection
                os_elem = host.find("os")
                if os_elem is not None:
                    osmatch = os_elem.find("osmatch")
                    if osmatch is not None:
                        host_data["os"] = {
                            "name": osmatch.get("name"),
                            "accuracy": osmatch.get("accuracy"),
                        }
                
                hosts.append(host_data)
        
        except ET.ParseError as e:
            logger.error(f"XML parse error: {e}")
        
        return {"hosts": hosts, "scan_file": xml_file}


class NucleiScanner:
    """Wrapper Nuclei pour la détection de vulnérabilités web"""
    
    async def scan(self, target: str, options: dict = {}) -> dict:
        """
        Lance un scan Nuclei sur une cible web.
        Utilise les templates de la communauté (gratuits).
        """
        scan_id = str(uuid.uuid4())[:8]
        output_file = SCAN_RESULTS_DIR / f"nuclei_{scan_id}.json"
        
        cmd = [
            "nuclei",
            "-target", target,
            "-json-export", str(output_file),
            "-severity", options.get("severity", "critical,high,medium"),
            "-timeout", str(options.get("timeout", 10)),
            "-bulk-size", "25",
            "-c", "50",
        ]
        
        # Templates spécifiques
        if options.get("templates"):
            cmd += ["-t", options["templates"]]
        else:
            # Templates par défaut : CVEs, exposures, misconfigs
            cmd += ["-t", "cves,exposures,misconfiguration,vulnerabilities"]
        
        if options.get("rate_limit"):
            cmd += ["-rl", str(options["rate_limit"])]
        
        logger.info(f"🔍 Nuclei scan: {target}")
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=options.get("max_duration", 1800)  # 30 min max
            )
            
            return self._parse_nuclei_output(str(output_file))
            
        except asyncio.TimeoutError:
            proc.kill()
            return {"findings": [], "error": "Scan timeout"}

    def _parse_nuclei_output(self, output_file: str) -> dict:
        """Parse le JSON output de Nuclei"""
        findings = []
        
        try:
            with open(output_file) as f:
                for line in f:
                    try:
                        finding = json.loads(line.strip())
                        findings.append({
                            "template_id": finding.get("template-id"),
                            "name": finding.get("info", {}).get("name"),
                            "severity": finding.get("info", {}).get("severity", "").upper(),
                            "description": finding.get("info", {}).get("description"),
                            "matched_at": finding.get("matched-at"),
                            "matcher_name": finding.get("matcher-name"),
                            "cve": finding.get("info", {}).get("classification", {}).get("cve-id", []),
                            "cvss_score": finding.get("info", {}).get("classification", {}).get("cvss-score"),
                            "tags": finding.get("info", {}).get("tags", []),
                            "reference": finding.get("info", {}).get("reference", []),
                            "remediation": finding.get("info", {}).get("remediation"),
                        })
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            logger.warning(f"Nuclei output file not found: {output_file}")
        
        return {"findings": findings, "total": len(findings)}


class TrivyScanner:
    """Wrapper Trivy pour les conteneurs et fichiers IaC"""
    
    async def scan_image(self, image: str) -> dict:
        """Scan d'une image Docker"""
        scan_id = str(uuid.uuid4())[:8]
        output_file = SCAN_RESULTS_DIR / f"trivy_{scan_id}.json"
        
        cmd = [
            "trivy", "image",
            "--format", "json",
            "--output", str(output_file),
            "--severity", "CRITICAL,HIGH,MEDIUM",
            image,
        ]
        
        logger.info(f"🔍 Trivy scan image: {image}")
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        
        return self._parse_trivy_output(str(output_file))

    async def scan_filesystem(self, path: str) -> dict:
        """Scan d'un filesystem ou repo IaC"""
        scan_id = str(uuid.uuid4())[:8]
        output_file = SCAN_RESULTS_DIR / f"trivy_fs_{scan_id}.json"
        
        cmd = [
            "trivy", "fs",
            "--format", "json",
            "--output", str(output_file),
            "--scanners", "vuln,secret,config",
            path,
        ]
        
        proc = await asyncio.create_subprocess_exec(*cmd,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await proc.communicate()
        
        return self._parse_trivy_output(str(output_file))

    def _parse_trivy_output(self, output_file: str) -> dict:
        """Parse le JSON Trivy"""
        try:
            with open(output_file) as f:
                data = json.load(f)
            
            vulnerabilities = []
            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    vulnerabilities.append({
                        "cve_id": vuln.get("VulnerabilityID"),
                        "package": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "severity": vuln.get("Severity", "UNKNOWN"),
                        "title": vuln.get("Title"),
                        "description": vuln.get("Description"),
                        "cvss_v3": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                        "references": vuln.get("References", []),
                        "target": result.get("Target"),
                        "type": result.get("Type"),
                    })
            
            return {
                "vulnerabilities": vulnerabilities,
                "total": len(vulnerabilities),
                "artifact": data.get("ArtifactName"),
            }
        except (FileNotFoundError, json.JSONDecodeError) as e:
            return {"vulnerabilities": [], "error": str(e)}


class ScanOrchestrator:
    """Orchestre les différents scanners selon le type de cible"""
    
    def __init__(self):
        self.nmap = NmapScanner()
        self.nuclei = NucleiScanner()
        self.trivy = TrivyScanner()

    async def run_infrastructure_scan(self, target: str, options: dict = {}) -> dict:
        """Scan complet d'une infrastructure (IP/range)"""
        results = {"target": target, "started_at": datetime.utcnow().isoformat()}
        
        # 1. Découverte Nmap
        logger.info(f"Phase 1: Nmap discovery on {target}")
        nmap_results = await self.nmap.scan(target, options)
        results["nmap"] = nmap_results
        
        # 2. Pour chaque host web trouvé, scan Nuclei
        web_hosts = []
        for host in nmap_results.get("hosts", []):
            for port in host.get("ports", []):
                if port["port"] in [80, 443, 8080, 8443]:
                    scheme = "https" if port["port"] in [443, 8443] else "http"
                    web_hosts.append(f"{scheme}://{host['ip']}:{port['port']}")
        
        if web_hosts and options.get("include_nuclei", True):
            logger.info(f"Phase 2: Nuclei scan on {len(web_hosts)} web services")
            nuclei_results = []
            for web_target in web_hosts[:5]:  # Limite à 5 pour la perf
                result = await self.nuclei.scan(web_target)
                nuclei_results.append({"target": web_target, **result})
            results["nuclei"] = nuclei_results
        
        results["completed_at"] = datetime.utcnow().isoformat()
        return results

    async def run_container_scan(self, image: str) -> dict:
        """Scan d'une image container"""
        return await self.trivy.scan_image(image)


# Singleton
scan_orchestrator = ScanOrchestrator()
