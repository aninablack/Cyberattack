# Global Cyber Threat Intelligence Dashboard

This dashboard provides:
- Attack hotspot map (global coordinates)
- Predictive risk visualization (7-day trend)
- Alert prioritization engine (KEV + EPSS + confidence + criticality + recency)
- Incident response playbook generator
- Real-time connector catalog for threat feeds

## Run Frontend

```bash
cd /path/to/cyber-threat-dashboard
python3 -m http.server 8080
```

Then open `http://localhost:8080`.

## Production Readiness (Netlify + GitHub Snapshot via Gist)

### 1) Deploy frontend to Netlify

Deploy this project root as a static site:
- Publish directory: `.`
- Build command: *(none required)*

### 2) Enable scheduled snapshot generation in GitHub

This repo includes:
- `.github/workflows/live-snapshot.yml`
- `scripts/generate_live_snapshot.py`

Every 30 minutes the workflow generates a validated snapshot and commits
`data/live-threats.json` only when `snapshot_mode` is `live`. Netlify then deploys
the updated static data file. Degraded refreshes leave the last published file unchanged.

Add optional API secrets in GitHub:
- `NVD_API_KEY`
- `ABUSEIPDB_API_KEY`
- `ABUSECH_API_KEY`
- `OTX_API_KEY`
- `CF_API_TOKEN`
- `URLSCAN_API_KEY`

Path in GitHub:
- `Settings` -> `Secrets and variables` -> `Actions` -> `New repository secret`

### 3) Run first snapshot manually

In GitHub:
- `Actions` -> `Refresh Live Snapshot` -> `Run workflow`

After it completes, the dashboard reads the committed `./data/live-threats.json`.
No separate snapshot URL or always-on backend is required.

## Map Basemap

The map uses local Natural Earth country geometry rendered as crisp Leaflet
vectors. Its land, borders, grid, labels, and ocean are styled with the dashboard
palette, with no map API key or external tile service required.

## Run Live Snapshot Locally (optional)

```bash
cd '/Users/aninablack/Documents/New project/cyber-threat-dashboard'
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
python scripts/generate_live_snapshot.py
```

This writes/refreshes:
- `data/live-threats.json`

### Optional per-feed caps (env)

You can tune feed volume without code edits by exporting env vars before running snapshot generation:

```bash
export MAX_THREATFOX_ROWS=350
export MAX_SPAMHAUS_CIDRS=250
export MAX_FIREHOL_IPS=250
export MAX_URLHAUS_ROWS=200
export MAX_PHISHTANK_ROWS=120
export MAX_PULSEDIVE_ROWS=140
export MAX_CIRCL_ROWS=80
export MAX_URL_DNS_HOSTS=120
export MAX_RANSOMWARE_LIVE_ROWS=120
export MAX_DDOS_TELEMETRY_ROWS=120
export MAX_CISA_ALERT_ROWS=80
export MAX_TOTAL_EVENTS=450
```

Supported caps in `backend/main.py`:
- `MAX_KEV_FETCH` (default `300`)
- `MAX_EPSS_SAMPLE` (default `100`)
- `MAX_THREATFOX_ROWS` (default `500`)
- `MAX_OPENPHISH_ROWS` (default `120`)
- `MAX_URLHAUS_ROWS` (default `250`)
- `MAX_OTX_PULSES` (default `40`)
- `MAX_OTX_IP_ROWS` (default `140`)
- `MAX_PHISHTANK_ROWS` (default `120`)
- `MAX_PULSEDIVE_ROWS` (default `140`)
- `MAX_CIRCL_ROWS` (default `80`)
- `MAX_URL_DNS_HOSTS` (default `120`)
- `MAX_RANSOMWARE_LIVE_ROWS` (default `120`)
- `MAX_DDOS_TELEMETRY_ROWS` (default `120`)
- `MAX_CISA_ALERT_ROWS` (default `80`)
- `MAX_IP_GEO_INPUT` (default `20`)
- `MAX_FEODO_ROWS` (default `400`)
- `MAX_SPAMHAUS_CIDRS` (default `300`)
- `MAX_FIREHOL_IPS` (default `350`)
- `MAX_REPUTATION_IP_EVENTS` (default `80`)
- `MAX_KEV_EVENTS` (default `120`)
- `MAX_CONTEXT_EVENTS` (default `40`)
- `MAX_TOTAL_EVENTS` (default `500`)

Optional API keys:
- `OTX_API_KEY` for AlienVault OTX
- `PULSEDIVE_API_KEY` for Pulsedive (disabled when unset; keep credentials out of request URLs and application logs)
- `CF_API_TOKEN` for Cloudflare Radar API access (optional; improves ddos telemetry coverage)
- `GREYNOISE_API_KEY` for GreyNoise enrichment
- `ABUSEIPDB_API_KEY` for AbuseIPDB enrichment

Snapshot integrity rules:

- The browser labels a snapshot `LIVE` only when it is explicitly generated in live mode and is no more than 45 minutes old.
- Stale, degraded, and last-good fallback snapshots are labeled accordingly and are never republished as fresh.
- The live map includes only source-derived, IP-geolocated, or clearly labeled country-centroid coordinates. Historical context and synthetic regional projections are excluded.
- Indicators without defensible coordinates remain in the alert stream with `locationClass: not-mapped`.

## Historical Map Mode

- Dataset file: `data/historical-threats.json`
- In UI use `Map Mode`:
  - `Live`
  - `Historical (2016-2026)` (default historical window, 10 years)
- `Historical window` selector:
  - `10 years (2016-2026)` default
  - `5 years (2021-2026)` optional focused view

## Real-time feed recommendations

1. CISA KEV Catalog (authoritative exploited CVEs)
2. NVD API 2.0 (CVE metadata)
3. FIRST EPSS API (exploit probability)
4. abuse.ch ThreatFox (IOC feed)
5. GreyNoise API (internet scanning context)
6. AbuseIPDB (abusive IP reputation)

## Alert prioritization model

```
PriorityScore = 0.35*KEV + 0.25*EPSS + 0.15*Confidence + 0.15*AssetCriticality + 0.10*Recency
```

Scale all inputs to 0-100.

## Report ingestion note

This dashboard is now grounded with metrics extracted from:
- `data/Reports/*.txt`
- `data/Screenshots/*` (OCR via tesseract)

Curated extracted metrics are stored in:
- `data/report-insights.json`

You can keep updating `data/report-insights.json` as you add more report stats.
