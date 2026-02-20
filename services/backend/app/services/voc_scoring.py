"""
VOC Scoring Engine
==================
Priorisation intelligente au-delà du CVSS.

Score VOC = f(CVSS, Exposition, Criticité Métier, Exploitabilité Réelle, Environnement)

Formule :
  VOC_score = (
      cvss_weight       * cvss_normalized      +   # Score technique de base
      exposure_weight   * exposure_score        +   # Est-il exposé sur internet ?
      business_weight   * business_score        +   # Criticité du système touché
      exploit_weight    * exploitability_score  +   # Y a-t-il un exploit actif ?
      env_weight        * environment_factor        # Prod vs Dev
  ) * kev_multiplier                               # Bonus si dans CISA KEV
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class EnvironmentType(str, Enum):
    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"
    TEST = "TEST"


@dataclass
class VulnerabilityContext:
    """Contexte complet pour le calcul du score VOC"""
    # Données techniques
    cvss_score: float                          # 0-10
    cve_id: Optional[str] = None
    
    # Exposition
    is_internet_exposed: bool = False          # Asset exposé sur internet
    port_exposed: Optional[int] = None        # Port spécifique exposé
    
    # Criticité métier
    business_criticality: int = 3             # 1-5 (5 = mission critical)
    
    # Exploitabilité réelle (depuis enrichissement)
    is_in_kev: bool = False                   # CISA Known Exploited Vuln
    exploit_available: bool = False           # Exploit public disponible
    exploit_maturity: Optional[str] = None   # POC | FUNCTIONAL | HIGH
    epss_score: Optional[float] = None       # 0-1 (probabilité d'exploitation 30j)
    greynoise_noise: bool = False             # Exploité massivement sur internet
    
    # Environnement
    environment: EnvironmentType = EnvironmentType.PRODUCTION


class VOCScoringEngine:
    """
    Moteur de scoring contextualisé VOC.
    Retourne un score entre 0 et 100.
    """

    # Poids des composantes
    WEIGHTS = {
        "cvss": 0.25,          # CVSS reste une base mais pas dominant
        "exposure": 0.25,      # Exposition internet = facteur majeur
        "business": 0.20,      # Impact métier
        "exploitability": 0.20, # Exploitabilité réelle
        "environment": 0.10,   # Criticité de l'environnement
    }

    # Facteurs d'environnement
    ENVIRONMENT_FACTORS = {
        EnvironmentType.PRODUCTION: 1.0,
        EnvironmentType.STAGING: 0.6,
        EnvironmentType.DEVELOPMENT: 0.3,
        EnvironmentType.TEST: 0.2,
    }

    # Maturité des exploits
    EXPLOIT_MATURITY_SCORES = {
        "HIGH": 1.0,
        "FUNCTIONAL": 0.8,
        "POC": 0.5,
        None: 0.0,
    }

    def calculate(self, ctx: VulnerabilityContext) -> dict:
        """
        Calcule le score VOC et retourne le détail de chaque composante.
        """
        # 1. Score CVSS normalisé (0→10 mappé sur 0→1)
        cvss_normalized = min(ctx.cvss_score / 10.0, 1.0)

        # 2. Score d'exposition (0→1)
        exposure_score = self._calculate_exposure(ctx)

        # 3. Score criticité métier (0→1)
        business_score = (ctx.business_criticality - 1) / 4.0  # 1-5 → 0-1

        # 4. Score d'exploitabilité réelle (0→1)
        exploitability_score = self._calculate_exploitability(ctx)

        # 5. Facteur environnement (0→1)
        environment_factor = self.ENVIRONMENT_FACTORS[ctx.environment]

        # Score pondéré (0→1)
        raw_score = (
            self.WEIGHTS["cvss"] * cvss_normalized +
            self.WEIGHTS["exposure"] * exposure_score +
            self.WEIGHTS["business"] * business_score +
            self.WEIGHTS["exploitability"] * exploitability_score +
            self.WEIGHTS["environment"] * environment_factor
        )

        # Multiplicateur CISA KEV : vulnérabilité activement exploitée → boost
        if ctx.is_in_kev:
            raw_score = min(raw_score * 1.3, 1.0)

        # Score final sur 100
        final_score = round(raw_score * 100, 2)

        return {
            "voc_score": final_score,
            "severity": self._score_to_severity(final_score),
            "components": {
                "cvss_normalized": round(cvss_normalized * 10, 2),
                "exposure_score": round(exposure_score * 10, 2),
                "business_score": round(business_score * 10, 2),
                "exploitability_score": round(exploitability_score * 10, 2),
                "environment_factor": round(environment_factor * 10, 2),
            },
            "kev_boost_applied": ctx.is_in_kev,
            "priority_reason": self._build_priority_reason(ctx, final_score),
        }

    def _calculate_exposure(self, ctx: VulnerabilityContext) -> float:
        """Score d'exposition basé sur l'accessibilité réseau"""
        score = 0.0
        
        if ctx.is_internet_exposed:
            score += 0.7
            # Ports très exposés (web, ssh, rdp)
            if ctx.port_exposed in [80, 443, 8080, 8443]:
                score += 0.2
            elif ctx.port_exposed in [22, 3389, 23]:
                score += 0.3
            else:
                score += 0.1
        else:
            score = 0.2  # Interne mais toujours un risque
            
        return min(score, 1.0)

    def _calculate_exploitability(self, ctx: VulnerabilityContext) -> float:
        """Score d'exploitabilité basé sur les données de threat intel"""
        score = 0.0

        # EPSS = probabilité d'exploitation dans les 30 prochains jours
        if ctx.epss_score is not None:
            score += ctx.epss_score * 0.4

        # Exploit disponible
        if ctx.exploit_available:
            exploit_bonus = self.EXPLOIT_MATURITY_SCORES.get(ctx.exploit_maturity, 0.3)
            score += exploit_bonus * 0.3

        # GreyNoise : exploitation massive observée sur internet
        if ctx.greynoise_noise:
            score += 0.3

        # CISA KEV : preuve d'exploitation réelle
        if ctx.is_in_kev:
            score = max(score, 0.9)

        return min(score, 1.0)

    def _score_to_severity(self, score: float) -> str:
        """Convertit le score VOC en niveau de sévérité"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "INFO"

    def _build_priority_reason(self, ctx: VulnerabilityContext, score: float) -> str:
        """Génère une explication humaine de la priorité"""
        reasons = []
        
        if ctx.is_in_kev:
            reasons.append("⚠️ Figurant dans la liste CISA KEV (exploitation confirmée)")
        if ctx.greynoise_noise:
            reasons.append("🔴 Exploitation massive observée sur internet (GreyNoise)")
        if ctx.epss_score and ctx.epss_score > 0.5:
            reasons.append(f"🎯 EPSS: {ctx.epss_score:.1%} de probabilité d'exploitation (30j)")
        if ctx.is_internet_exposed:
            reasons.append("🌐 Asset exposé sur internet")
        if ctx.business_criticality >= 4:
            reasons.append(f"🏭 Système critique métier (niveau {ctx.business_criticality}/5)")
        if ctx.environment == EnvironmentType.PRODUCTION:
            reasons.append("⚙️ Environnement de production")
        if ctx.exploit_available:
            reasons.append(f"💣 Exploit disponible (maturité: {ctx.exploit_maturity or 'POC'})")

        if not reasons:
            reasons.append("Vulnérabilité standard sans facteur aggravant identifié")

        return " | ".join(reasons)


# Singleton
scoring_engine = VOCScoringEngine()
