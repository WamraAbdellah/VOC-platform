# 🛡️ VOC Platform - Vulnerability Operation Center

Plateforme complète de gestion des vulnérabilités : détection, enrichissement, scoring contextualisé et remédiation.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         NGINX (port 80)                      │
│              Reverse proxy Frontend + API                    │
└────────────────┬─────────────────┬───────────────────────────┘
                 │                 │
    ┌────────────▼───┐    ┌────────▼──────────┐
    │  Frontend      │    │   Backend API      │
    │  React         │    │   FastAPI + Python │
    │  (port 3000)   │    │   (port 8000)     │
    └────────────────┘    └────────┬───────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
    ┌─────────▼──────┐  ┌─────────▼──────┐  ┌─────────▼──────┐
    │  PostgreSQL     │  │  Redis         │  │  Celery Workers │
    │  (port 5432)    │  │  (port 6379)   │  │  (4 concurrency)│
    └────────────────┘  └────────────────┘  └────────────────┘
              │
    ┌─────────▼──────┐  ┌────────────────┐  ┌────────────────┐
    │  Scanner Svc   │  │  Enrichment Svc│  │  Grafana       │
    │  Nmap/Nuclei   │  │  NVD/EPSS/KEV  │  │  (port 3001)   │
    │  Trivy/Nikto   │  │  GreyNoise     │  │                │
    └────────────────┘  └────────────────┘  └────────────────┘
```

## APIs Gratuites Intégrées

| API | Données | Limite |
|-----|---------|--------|
| **NVD (NIST)** | CVE details, CVSS | 50 req/30s (avec clé) |
| **CISA KEV** | Exploitations confirmées | Illimitée |
| **EPSS (FIRST)** | Probabilité exploitation 30j | Illimitée |
| **OSV.dev** | Vulnérabilités open-source | Illimitée |
| **CVE Circl** | Exploits disponibles | Illimitée |
| **GreyNoise** | Exploitation in-the-wild | 1000/jour |

## Outils de Scan Intégrés

| Outil | Usage | Licence |
|-------|-------|---------|
| **Nmap** | Découverte réseau, ports | GPL |
| **Nuclei** | Web app vulnérabilités | MIT |
| **Trivy** | Containers, IaC | Apache 2.0 |
| **Nikto** | Web server scan | GPL |

## 🚀 Démarrage Rapide

### 1. Prérequis
- Docker & Docker Compose v2
- 8 GB RAM minimum
- Ports libres : 80, 3001, 5432, 5555, 6379, 8000

### 2. Configuration
```bash
cp .env.example .env
# Optionnel mais recommandé :
# Obtenez une clé NVD gratuite sur https://nvd.nist.gov/developers/request-an-api-key
# Éditez .env et renseignez NVD_API_KEY
```

### 3. Lancer la plateforme
```bash
docker compose up -d
```

### 4. Accès
| Service | URL | Credentials |
|---------|-----|-------------|
| **VOC Dashboard** | http://localhost | - |
| **API Docs** | http://localhost:8000/api/docs | - |
| **Grafana** | http://localhost:3001 | admin/admin |
| **Flower (Celery)** | http://localhost:5555 | - |

## 📊 Scoring VOC - Au-delà du CVSS

Le score VOC contextualisé intègre 5 dimensions :

```
VOC_score (0-100) = 
    25% × CVSS_normalisé        # Base technique
  + 25% × Exposition_réseau     # Internet exposed ?
  + 20% × Criticité_métier      # Asset business impact
  + 20% × Exploitabilité_réelle # EPSS + exploits + GreyNoise
  + 10% × Facteur_environnement # Prod > Staging > Dev
  × Bonus_KEV (×1.3 si CISA KEV)
```

### Exemples de priorisation

| Scénario | CVSS | VOC Score | Raison |
|----------|------|-----------|--------|
| CVE critique sur serveur interne non exposé | 9.8 | 45 | Pas d'exposition internet, dev env |
| CVE moyenne sur serveur web production KEV | 5.9 | 88 | KEV + internet + prod |
| Log4Shell sur système critique exposé | 10.0 | 97 | Tous les facteurs au max |
| CVE haute sur PC test non connecté | 7.5 | 28 | Pas d'exposition, env test |

## 🔄 Workflows VOC

### Détection → Remédiation
```
SCAN (Nmap/Nuclei/Trivy)
  ↓
INGESTION (parser & normaliser)
  ↓
ENRICHISSEMENT (NVD + EPSS + KEV + GreyNoise) [async]
  ↓
SCORING VOC (calcul contextualisé)
  ↓
QUALIFICATION (analyst review)
  ↓
TICKET DE REMÉDIATION (assignation)
  ↓
REMÉDIATION (patch/mitigation)
  ↓
RE-SCAN (vérification)
  ↓
CLÔTURE
```

### Tâches Automatisées (Celery Beat)
- `06:00` — Sync CISA KEV
- `07:00` — Snapshot KPI quotidien  
- `Lun 03:00` — Sync scores EPSS
- `Toutes les heures` — Alertes CRITICAL non traités
- `Toutes les 6h` — Recalcul scores VOC

## 📈 KPIs Clés

- **MTTR** (Mean Time To Remediate) par sévérité
- **Taux de remédiation** global
- **Backlog age** moyen
- **KEV unpatched** count
- **Score VOC moyen** par asset

## Structure du Projet

```
voc-platform/
├── docker-compose.yml
├── .env
├── db/
│   └── init.sql              # Schéma PostgreSQL complet
├── nginx/
│   └── nginx.conf
├── services/
│   ├── backend/              # FastAPI
│   │   └── app/
│   │       ├── api/          # Endpoints REST
│   │       ├── services/     # VOC Scoring, Enrichissement
│   │       └── tasks/        # Celery tasks async
│   ├── frontend/             # React Dashboard
│   │   └── src/App.js        # Application complète
│   ├── scanner/              # Nmap, Nuclei, Trivy wrappers
│   └── enrichment/           # Worker Redis enrichissement
└── dashboards/               # Grafana provisioning
```

## 🛑 Notes Sécurité

- ⚠️ Changez les mots de passe dans `.env` avant tout usage en production
- ⚠️ Les scans Nmap et Nuclei ne doivent être lancés que sur vos propres systèmes
- ⚠️ Configurez les CORS pour votre domaine en production

## Phase 2 - Roadmap

- [ ] Intégration OpenVAS/Greenbone Community
- [ ] Connecteur Jira/ServiceNow pour les tickets
- [ ] Export PDF des rapports client
- [ ] Module d'acceptation du risque avec workflow de validation
- [ ] API webhooks pour alertes Slack/Teams
- [ ] SLA tracking par client
