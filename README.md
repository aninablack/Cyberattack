# Global Cyber Threat Intelligence Dashboard

This dashboard provides:
- Attack hotspot map (global coordinates)
- Predictive risk visualization (7-day trend)
- Alert prioritization engine (KEV + EPSS + confidence + criticality + recency)
- Incident response playbook generator
- Real-time connector catalog for threat feeds

## Run Frontend

```bash
cd '/Users/aninablack/Documents/New project/cyber-threat-dashboard'
python3 -m http.server 8080
```

Then open `http://localhost:8080`.

## Production Readiness (Netlify + Render)

### 1) Deploy backend to Render

This repo includes [`render.yaml`](/Users/aninablack/Documents/New%20project/cyber-threat-dashboard/render.yaml) for a Python web service.

Render settings are already defined:
- root: `backend/`
- build: `pip install -r requirements.txt`
- start: `uvicorn main:app --host 0.0.0.0 --port $PORT`

Set env vars in Render dashboard:
- Required for optional feeds:
  - `SHODAN_API_KEY`
  - `CENSYS_API_ID`
  - `CENSYS_API_SECRET`
  - `URLSCAN_API_KEY` (optional, improves stability/rate limits)
- Existing optional keys:
  - `OTX_API_KEY`
  - `PULSEDIVE_API_KEY`
  - `CF_API_TOKEN`
  - `ABUSEIPDB_API_KEY`

After deploy, copy your Render API URL, e.g.:
- `https://cyber-threat-api.onrender.com`

### 2) Deploy frontend to Netlify

Deploy this project root as a static site:
- Publish directory: `.`
- Build command: *(none required)*

### 3) Point frontend to production API

Set API base URL in browser (one-time):

```js
localStorage.setItem("CYBER_API_BASE", "https://YOUR-RENDER-SERVICE.onrender.com");
location.reload();
```

To clear and return to localhost behavior:

```js
localStorage.removeItem("CYBER_API_BASE");
location.reload();
```

API resolution behavior in frontend:
- If `window.CYBER_API_BASE` or `localStorage.CYBER_API_BASE` is set -> uses that.
- On localhost -> uses `127.0.0.1:8090` / `localhost:8090`.
- On non-localhost with no override -> uses same-origin `/api/...`.

### 4) Optional: set API base without localStorage

You can inject before `app.js` in `index.html`:

```html
<script>window.CYBER_API_BASE = "https://YOUR-RENDER-SERVICE.onrender.com";</script>
```

## Map Provider (MapTiler)

The map uses MapTiler when a key is present, otherwise it falls back to CARTO dark tiles.

Set your MapTiler key in browser localStorage:

```js
localStorage.setItem("MAPTILER_KEY", "YOUR_MAPTILER_KEY")
location.reload()
```

## Run Live Data API (optional but recommended)

```bash
cd '/Users/aninablack/Documents/New project/cyber-threat-dashboard/backend'
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8090
```

API endpoint:

- `http://localhost:8090/api/live-threats`

The dashboard automatically tries this live endpoint first and falls back to local sample data if unavailable.

### Optional per-feed caps (env)

You can tune live feed volume without code edits by exporting env vars before starting `uvicorn`:

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
- `MAX_IP_GEO_INPUT` (default `500`)
- `MAX_FEODO_ROWS` (default `400`)
- `MAX_SPAMHAUS_CIDRS` (default `300`)
- `MAX_FIREHOL_IPS` (default `350`)
- `MAX_REPUTATION_IP_EVENTS` (default `80`)
- `MAX_KEV_EVENTS` (default `120`)
- `MAX_CONTEXT_EVENTS` (default `40`)
- `MAX_TOTAL_EVENTS` (default `500`)

Optional API keys:
- `OTX_API_KEY` for AlienVault OTX
- `PULSEDIVE_API_KEY` for Pulsedive
- `CF_API_TOKEN` for Cloudflare Radar API access (optional; improves ddos telemetry coverage)
- `GREYNOISE_API_KEY` for GreyNoise enrichment
- `ABUSEIPDB_API_KEY` for AbuseIPDB enrichment

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
