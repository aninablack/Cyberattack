from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse
import xml.etree.ElementTree as ET

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Cyber Threat Live API", version="0.1.0")
logger = logging.getLogger("cyberdash.feeds")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "900"))


def load_local_env_file() -> None:
    # Lightweight .env loader to keep backend config local without extra deps.
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return
    try:
        for raw in env_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("\"").strip("'")
            # Allow .env values to populate missing or blank environment keys.
            if key and (key not in os.environ or not str(os.environ.get(key, "")).strip()):
                os.environ[key] = value
    except Exception:
        # Non-fatal: environment variables can still come from shell.
        return


load_local_env_file()
DEBUG_FEEDS = os.getenv("DEBUG_FEEDS", "").strip().lower() in {"1", "true", "yes", "on"}

NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
ABUSECH_API_KEY = os.getenv("ABUSECH_API_KEY", "").strip()
OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()
PULSEDIVE_API_KEY = os.getenv("PULSEDIVE_API_KEY", "").strip()
CF_API_TOKEN = os.getenv("CF_API_TOKEN", "").strip()
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "").strip()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "").strip()
CENSYS_API_ID = os.getenv("CENSYS_API_ID", "").strip()
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "").strip()


def debug_feed(source: str, message: str) -> None:
    if DEBUG_FEEDS:
        logger.info("[%s] %s", source, message)


def env_int(name: str, default: int, min_value: int = 1, max_value: int = 5000) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(min_value, min(max_value, value))


MAX_KEV_FETCH = env_int("MAX_KEV_FETCH", 300)
MAX_EPSS_SAMPLE = env_int("MAX_EPSS_SAMPLE", 100)
MAX_THREATFOX_ROWS = env_int("MAX_THREATFOX_ROWS", 500)
MAX_OPENPHISH_ROWS = env_int("MAX_OPENPHISH_ROWS", 120)
MAX_URLHAUS_ROWS = env_int("MAX_URLHAUS_ROWS", 250)
MAX_OTX_PULSES = env_int("MAX_OTX_PULSES", 40)
MAX_OTX_IP_ROWS = env_int("MAX_OTX_IP_ROWS", 140)
MAX_PHISHTANK_ROWS = env_int("MAX_PHISHTANK_ROWS", 120)
MAX_PULSEDIVE_ROWS = env_int("MAX_PULSEDIVE_ROWS", 140)
MAX_CIRCL_ROWS = env_int("MAX_CIRCL_ROWS", 80)
MAX_URL_DNS_HOSTS = env_int("MAX_URL_DNS_HOSTS", 120)
MAX_RANSOMWARE_LIVE_ROWS = env_int("MAX_RANSOMWARE_LIVE_ROWS", 120)
MAX_DDOS_TELEMETRY_ROWS = env_int("MAX_DDOS_TELEMETRY_ROWS", 120)
MAX_CISA_ALERT_ROWS = env_int("MAX_CISA_ALERT_ROWS", 80)
MAX_URLSCAN_ROWS = env_int("MAX_URLSCAN_ROWS", 40)
MAX_SHODAN_ROWS = env_int("MAX_SHODAN_ROWS", 40)
MAX_CENSYS_ROWS = env_int("MAX_CENSYS_ROWS", 40)
MAX_MALWAREBAZAAR_ROWS = env_int("MAX_MALWAREBAZAAR_ROWS", 80)
MAX_DEPSDEV_EVENTS = env_int("MAX_DEPSDEV_EVENTS", 40)
MAX_OSV_EVENTS = env_int("MAX_OSV_EVENTS", 60)
MAX_IP_GEO_INPUT = env_int("MAX_IP_GEO_INPUT", 500)
MAX_FEODO_ROWS = env_int("MAX_FEODO_ROWS", 400)
MAX_SPAMHAUS_CIDRS = env_int("MAX_SPAMHAUS_CIDRS", 120)
MAX_FIREHOL_IPS = env_int("MAX_FIREHOL_IPS", 140)
MAX_EMERGINGTHREATS_IPS = env_int("MAX_EMERGINGTHREATS_IPS", 120)
MAX_GREENSNOW_IPS = env_int("MAX_GREENSNOW_IPS", 120)
MAX_REPUTATION_IP_EVENTS = env_int("MAX_REPUTATION_IP_EVENTS", 80)
MAX_KEV_EVENTS = env_int("MAX_KEV_EVENTS", 120)
MAX_TOTAL_EVENTS = env_int("MAX_TOTAL_EVENTS", 500)
MAX_CONTEXT_EVENTS = env_int("MAX_CONTEXT_EVENTS", 40)
PULSEDIVE_DAILY_REQUEST_LIMIT = env_int("PULSEDIVE_DAILY_REQUEST_LIMIT", 45, min_value=1, max_value=5000)
ABUSEIPDB_DAILY_CHECK_LIMIT = env_int("ABUSEIPDB_DAILY_CHECK_LIMIT", 900, min_value=1, max_value=5000)
ABUSEIPDB_DAILY_HEADROOM = env_int("ABUSEIPDB_DAILY_HEADROOM", 200, min_value=0, max_value=2000)
MAX_ABUSEIPDB_CHECKS_PER_REFRESH = env_int("MAX_ABUSEIPDB_CHECKS_PER_REFRESH", 20, min_value=1, max_value=200)
ABUSECH_DAILY_REQUEST_LIMIT = env_int("ABUSECH_DAILY_REQUEST_LIMIT", 300, min_value=1, max_value=5000)
DEPSDEV_DAILY_REQUEST_LIMIT = env_int("DEPSDEV_DAILY_REQUEST_LIMIT", 180, min_value=1, max_value=5000)
OSV_DAILY_REQUEST_LIMIT = env_int("OSV_DAILY_REQUEST_LIMIT", 220, min_value=1, max_value=5000)
ABUSEIPDB_REFRESH_EVERY = env_int("ABUSEIPDB_REFRESH_EVERY", 3, min_value=1, max_value=48)
PULSEDIVE_REFRESH_EVERY = env_int("PULSEDIVE_REFRESH_EVERY", 3, min_value=1, max_value=48)
DEPSDEV_REFRESH_EVERY = env_int("DEPSDEV_REFRESH_EVERY", 3, min_value=1, max_value=48)
OSV_REFRESH_EVERY = env_int("OSV_REFRESH_EVERY", 2, min_value=1, max_value=48)
CISA_REFRESH_EVERY = env_int("CISA_REFRESH_EVERY", 3, min_value=1, max_value=48)
URLSCAN_REFRESH_EVERY = env_int("URLSCAN_REFRESH_EVERY", 4, min_value=1, max_value=96)
SHODAN_REFRESH_EVERY = env_int("SHODAN_REFRESH_EVERY", 8, min_value=1, max_value=96)
CENSYS_REFRESH_EVERY = env_int("CENSYS_REFRESH_EVERY", 8, min_value=1, max_value=96)
URLSCAN_DAILY_REQUEST_LIMIT = env_int("URLSCAN_DAILY_REQUEST_LIMIT", 120, min_value=1, max_value=5000)
SHODAN_DAILY_REQUEST_LIMIT = env_int("SHODAN_DAILY_REQUEST_LIMIT", 40, min_value=1, max_value=2000)
CENSYS_DAILY_REQUEST_LIMIT = env_int("CENSYS_DAILY_REQUEST_LIMIT", 40, min_value=1, max_value=2000)

state: dict[str, Any] = {
    "last_fetch": 0.0,
    "events": [],
    "sources": {},
    "source_health": {},
    "refresh_seq": 0,
}
PULSEDIVE_COOLDOWN_UNTIL = 0.0
CISA_COOLDOWN_UNTIL = 0.0
PULSEDIVE_BUDGET_PATH = Path(__file__).resolve().parent / ".pulsedive_budget.json"
PULSEDIVE_BUDGET_STATE: dict[str, Any] = {"day": "", "used": 0}
ABUSEIPDB_BUDGET_PATH = Path(__file__).resolve().parent / ".abuseipdb_budget.json"
ABUSEIPDB_BUDGET_STATE: dict[str, Any] = {"day": "", "used": 0}
ABUSECH_BUDGET_PATH = Path(__file__).resolve().parent / ".abusech_budget.json"
ABUSECH_BUDGET_STATE: dict[str, Any] = {"day": "", "used": 0}
DEPSDEV_BUDGET_PATH = Path(__file__).resolve().parent / ".depsdev_budget.json"
DEPSDEV_BUDGET_STATE: dict[str, Any] = {"day": "", "used": 0}
OSV_BUDGET_PATH = Path(__file__).resolve().parent / ".osv_budget.json"
OSV_BUDGET_STATE: dict[str, Any] = {"day": "", "used": 0}
URLSCAN_BUDGET_PATH = Path(__file__).resolve().parent / ".urlscan_budget.json"
URLSCAN_BUDGET_STATE: dict[str, Any] = {"day": "", "used": 0}
SHODAN_BUDGET_PATH = Path(__file__).resolve().parent / ".shodan_budget.json"
SHODAN_BUDGET_STATE: dict[str, Any] = {"day": "", "used": 0}
CENSYS_BUDGET_PATH = Path(__file__).resolve().parent / ".censys_budget.json"
CENSYS_BUDGET_STATE: dict[str, Any] = {"day": "", "used": 0}
HISTORICAL_DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "historical-threats.json"

# Country centroids for approximate geolocation by country (not exact incident point).
COUNTRY_CENTROIDS = {
    "US": (37.0902, -95.7129),
    "GB": (55.3781, -3.4360),
    "DE": (51.1657, 10.4515),
    "FR": (46.2276, 2.2137),
    "NL": (52.1326, 5.2913),
    "SE": (60.1282, 18.6435),
    "PL": (51.9194, 19.1451),
    "UA": (48.3794, 31.1656),
    "RU": (61.5240, 105.3188),
    "CN": (35.8617, 104.1954),
    "IN": (20.5937, 78.9629),
    "SG": (1.3521, 103.8198),
    "JP": (36.2048, 138.2529),
    "KR": (35.9078, 127.7669),
    "BR": (-14.2350, -51.9253),
    "MX": (23.6345, -102.5528),
    "CA": (56.1304, -106.3468),
    "AU": (-25.2744, 133.7751),
    "ES": (40.4637, -3.7492),
    "IT": (41.8719, 12.5674),
}


def normalize_score(v: float, lo: float, hi: float) -> float:
    if hi <= lo:
        return 0.0
    return max(0.0, min(1.0, (v - lo) / (hi - lo)))


def utc_day_key(ts: float | None = None) -> str:
    dt = datetime.fromtimestamp(ts or time.time(), tz=timezone.utc)
    return dt.strftime("%Y-%m-%d")


def load_pulsedive_budget() -> None:
    global PULSEDIVE_BUDGET_STATE
    try:
        if PULSEDIVE_BUDGET_PATH.exists():
            raw = json.loads(PULSEDIVE_BUDGET_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                PULSEDIVE_BUDGET_STATE = {
                    "day": str(raw.get("day") or ""),
                    "used": int(raw.get("used") or 0),
                }
    except Exception:
        PULSEDIVE_BUDGET_STATE = {"day": "", "used": 0}


def save_pulsedive_budget() -> None:
    try:
        PULSEDIVE_BUDGET_PATH.write_text(json.dumps(PULSEDIVE_BUDGET_STATE), encoding="utf-8")
    except Exception:
        return


def reserve_pulsedive_request() -> bool:
    if PULSEDIVE_DAILY_REQUEST_LIMIT <= 0:
        return True
    today = utc_day_key()
    day = str(PULSEDIVE_BUDGET_STATE.get("day") or "")
    used = int(PULSEDIVE_BUDGET_STATE.get("used") or 0)
    if day != today:
        day = today
        used = 0
    if used >= PULSEDIVE_DAILY_REQUEST_LIMIT:
        PULSEDIVE_BUDGET_STATE["day"] = day
        PULSEDIVE_BUDGET_STATE["used"] = used
        save_pulsedive_budget()
        return False
    used += 1
    PULSEDIVE_BUDGET_STATE["day"] = day
    PULSEDIVE_BUDGET_STATE["used"] = used
    save_pulsedive_budget()
    return True


def load_abuseipdb_budget() -> None:
    global ABUSEIPDB_BUDGET_STATE
    try:
        if ABUSEIPDB_BUDGET_PATH.exists():
            raw = json.loads(ABUSEIPDB_BUDGET_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                ABUSEIPDB_BUDGET_STATE = {
                    "day": str(raw.get("day") or ""),
                    "used": int(raw.get("used") or 0),
                }
    except Exception:
        ABUSEIPDB_BUDGET_STATE = {"day": "", "used": 0}


def save_abuseipdb_budget() -> None:
    try:
        ABUSEIPDB_BUDGET_PATH.write_text(json.dumps(ABUSEIPDB_BUDGET_STATE), encoding="utf-8")
    except Exception:
        return


def reserve_abuseipdb_check() -> bool:
    if ABUSEIPDB_DAILY_CHECK_LIMIT <= 0:
        return True
    today = utc_day_key()
    day = str(ABUSEIPDB_BUDGET_STATE.get("day") or "")
    used = int(ABUSEIPDB_BUDGET_STATE.get("used") or 0)
    if day != today:
        day = today
        used = 0
    # Keep a fixed safety buffer so user-facing quota errors do not occur near limit.
    allowed_ceiling = max(0, ABUSEIPDB_DAILY_CHECK_LIMIT - ABUSEIPDB_DAILY_HEADROOM)
    if used >= allowed_ceiling:
        ABUSEIPDB_BUDGET_STATE["day"] = day
        ABUSEIPDB_BUDGET_STATE["used"] = used
        save_abuseipdb_budget()
        return False
    used += 1
    ABUSEIPDB_BUDGET_STATE["day"] = day
    ABUSEIPDB_BUDGET_STATE["used"] = used
    save_abuseipdb_budget()
    return True


def load_abusech_budget() -> None:
    global ABUSECH_BUDGET_STATE
    try:
        if ABUSECH_BUDGET_PATH.exists():
            raw = json.loads(ABUSECH_BUDGET_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                ABUSECH_BUDGET_STATE = {
                    "day": str(raw.get("day") or ""),
                    "used": int(raw.get("used") or 0),
                }
    except Exception:
        ABUSECH_BUDGET_STATE = {"day": "", "used": 0}


def save_abusech_budget() -> None:
    try:
        ABUSECH_BUDGET_PATH.write_text(json.dumps(ABUSECH_BUDGET_STATE), encoding="utf-8")
    except Exception:
        return


def reserve_abusech_request() -> bool:
    if ABUSECH_DAILY_REQUEST_LIMIT <= 0:
        return True
    today = utc_day_key()
    day = str(ABUSECH_BUDGET_STATE.get("day") or "")
    used = int(ABUSECH_BUDGET_STATE.get("used") or 0)
    if day != today:
        day = today
        used = 0
    if used >= ABUSECH_DAILY_REQUEST_LIMIT:
        ABUSECH_BUDGET_STATE["day"] = day
        ABUSECH_BUDGET_STATE["used"] = used
        save_abusech_budget()
        return False
    used += 1
    ABUSECH_BUDGET_STATE["day"] = day
    ABUSECH_BUDGET_STATE["used"] = used
    save_abusech_budget()
    return True


def load_depsdev_budget() -> None:
    global DEPSDEV_BUDGET_STATE
    try:
        if DEPSDEV_BUDGET_PATH.exists():
            raw = json.loads(DEPSDEV_BUDGET_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                DEPSDEV_BUDGET_STATE = {
                    "day": str(raw.get("day") or ""),
                    "used": int(raw.get("used") or 0),
                }
    except Exception:
        DEPSDEV_BUDGET_STATE = {"day": "", "used": 0}


def save_depsdev_budget() -> None:
    try:
        DEPSDEV_BUDGET_PATH.write_text(json.dumps(DEPSDEV_BUDGET_STATE), encoding="utf-8")
    except Exception:
        return


def reserve_depsdev_request() -> bool:
    if DEPSDEV_DAILY_REQUEST_LIMIT <= 0:
        return True
    today = utc_day_key()
    day = str(DEPSDEV_BUDGET_STATE.get("day") or "")
    used = int(DEPSDEV_BUDGET_STATE.get("used") or 0)
    if day != today:
        day = today
        used = 0
    if used >= DEPSDEV_DAILY_REQUEST_LIMIT:
        DEPSDEV_BUDGET_STATE["day"] = day
        DEPSDEV_BUDGET_STATE["used"] = used
        save_depsdev_budget()
        return False
    used += 1
    DEPSDEV_BUDGET_STATE["day"] = day
    DEPSDEV_BUDGET_STATE["used"] = used
    save_depsdev_budget()
    return True


def load_osv_budget() -> None:
    global OSV_BUDGET_STATE
    try:
        if OSV_BUDGET_PATH.exists():
            raw = json.loads(OSV_BUDGET_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                OSV_BUDGET_STATE = {"day": str(raw.get("day") or ""), "used": int(raw.get("used") or 0)}
    except Exception:
        OSV_BUDGET_STATE = {"day": "", "used": 0}


def save_osv_budget() -> None:
    try:
        OSV_BUDGET_PATH.write_text(json.dumps(OSV_BUDGET_STATE), encoding="utf-8")
    except Exception:
        return


def reserve_osv_request() -> bool:
    if OSV_DAILY_REQUEST_LIMIT <= 0:
        return True
    today = utc_day_key()
    day = str(OSV_BUDGET_STATE.get("day") or "")
    used = int(OSV_BUDGET_STATE.get("used") or 0)
    if day != today:
        day = today
        used = 0
    if used >= OSV_DAILY_REQUEST_LIMIT:
        OSV_BUDGET_STATE["day"] = day
        OSV_BUDGET_STATE["used"] = used
        save_osv_budget()
        return False
    used += 1
    OSV_BUDGET_STATE["day"] = day
    OSV_BUDGET_STATE["used"] = used
    save_osv_budget()
    return True


def load_urlscan_budget() -> None:
    global URLSCAN_BUDGET_STATE
    try:
        if URLSCAN_BUDGET_PATH.exists():
            raw = json.loads(URLSCAN_BUDGET_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                URLSCAN_BUDGET_STATE = {"day": str(raw.get("day") or ""), "used": int(raw.get("used") or 0)}
    except Exception:
        URLSCAN_BUDGET_STATE = {"day": "", "used": 0}


def save_urlscan_budget() -> None:
    try:
        URLSCAN_BUDGET_PATH.write_text(json.dumps(URLSCAN_BUDGET_STATE), encoding="utf-8")
    except Exception:
        return


def reserve_urlscan_request() -> bool:
    if URLSCAN_DAILY_REQUEST_LIMIT <= 0:
        return True
    today = utc_day_key()
    day = str(URLSCAN_BUDGET_STATE.get("day") or "")
    used = int(URLSCAN_BUDGET_STATE.get("used") or 0)
    if day != today:
        day = today
        used = 0
    if used >= URLSCAN_DAILY_REQUEST_LIMIT:
        URLSCAN_BUDGET_STATE["day"] = day
        URLSCAN_BUDGET_STATE["used"] = used
        save_urlscan_budget()
        return False
    used += 1
    URLSCAN_BUDGET_STATE["day"] = day
    URLSCAN_BUDGET_STATE["used"] = used
    save_urlscan_budget()
    return True


def load_shodan_budget() -> None:
    global SHODAN_BUDGET_STATE
    try:
        if SHODAN_BUDGET_PATH.exists():
            raw = json.loads(SHODAN_BUDGET_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                SHODAN_BUDGET_STATE = {"day": str(raw.get("day") or ""), "used": int(raw.get("used") or 0)}
    except Exception:
        SHODAN_BUDGET_STATE = {"day": "", "used": 0}


def save_shodan_budget() -> None:
    try:
        SHODAN_BUDGET_PATH.write_text(json.dumps(SHODAN_BUDGET_STATE), encoding="utf-8")
    except Exception:
        return


def reserve_shodan_request() -> bool:
    if SHODAN_DAILY_REQUEST_LIMIT <= 0:
        return True
    today = utc_day_key()
    day = str(SHODAN_BUDGET_STATE.get("day") or "")
    used = int(SHODAN_BUDGET_STATE.get("used") or 0)
    if day != today:
        day = today
        used = 0
    if used >= SHODAN_DAILY_REQUEST_LIMIT:
        SHODAN_BUDGET_STATE["day"] = day
        SHODAN_BUDGET_STATE["used"] = used
        save_shodan_budget()
        return False
    used += 1
    SHODAN_BUDGET_STATE["day"] = day
    SHODAN_BUDGET_STATE["used"] = used
    save_shodan_budget()
    return True


def load_censys_budget() -> None:
    global CENSYS_BUDGET_STATE
    try:
        if CENSYS_BUDGET_PATH.exists():
            raw = json.loads(CENSYS_BUDGET_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                CENSYS_BUDGET_STATE = {"day": str(raw.get("day") or ""), "used": int(raw.get("used") or 0)}
    except Exception:
        CENSYS_BUDGET_STATE = {"day": "", "used": 0}


def save_censys_budget() -> None:
    try:
        CENSYS_BUDGET_PATH.write_text(json.dumps(CENSYS_BUDGET_STATE), encoding="utf-8")
    except Exception:
        return


def reserve_censys_request() -> bool:
    if CENSYS_DAILY_REQUEST_LIMIT <= 0:
        return True
    today = utc_day_key()
    day = str(CENSYS_BUDGET_STATE.get("day") or "")
    used = int(CENSYS_BUDGET_STATE.get("used") or 0)
    if day != today:
        day = today
        used = 0
    if used >= CENSYS_DAILY_REQUEST_LIMIT:
        CENSYS_BUDGET_STATE["day"] = day
        CENSYS_BUDGET_STATE["used"] = used
        save_censys_budget()
        return False
    used += 1
    CENSYS_BUDGET_STATE["day"] = day
    CENSYS_BUDGET_STATE["used"] = used
    save_censys_budget()
    return True


load_pulsedive_budget()
load_abuseipdb_budget()
load_abusech_budget()
load_depsdev_budget()
load_osv_budget()
load_urlscan_budget()
load_shodan_budget()
load_censys_budget()


async def fetch_kev(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data = (await client.get(url, timeout=20)).json()
    out = []
    for v in data.get("vulnerabilities", [])[:MAX_KEV_FETCH]:
        out.append(
            {
                "cve": v.get("cveID"),
                "vendor": v.get("vendorProject", "Unknown"),
                "product": v.get("product", "Unknown"),
                "dateAdded": v.get("dateAdded"),
            }
        )
    return out


async def fetch_epss(client: httpx.AsyncClient, cves: list[str]) -> dict[str, float]:
    if not cves:
        return {}
    sample = sorted(set(cves))[:MAX_EPSS_SAMPLE]
    url = "https://api.first.org/data/v1/epss"
    params = {"cve": ",".join(sample)}
    data = (await client.get(url, params=params, timeout=20)).json()
    mapping = {}
    for r in data.get("data", []):
        cve = r.get("cve")
        try:
            mapping[cve] = float(r.get("epss", 0))
        except (TypeError, ValueError):
            mapping[cve] = 0.0
    return mapping


async def fetch_nvd_enrichment(client: httpx.AsyncClient, cves: list[str]) -> dict[str, dict[str, Any]]:
    # Free tier friendly: keep sample small, especially without API key.
    if not cves:
        return {}
    uniq = sorted(set([c for c in cves if isinstance(c, str)]))
    limit = 8 if not NVD_API_KEY else 20
    sample = uniq[:limit]
    out: dict[str, dict[str, Any]] = {}
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
    for cve in sample:
        try:
            data = (await client.get(f"{base}{quote(cve)}", headers=headers, timeout=20)).json()
        except Exception:
            continue
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            continue
        c = (vulns[0] or {}).get("cve", {})
        metrics = c.get("metrics", {})
        cvss = None
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(k) or []
            if arr:
                cvss = (arr[0] or {}).get("cvssData", {}).get("baseScore")
                if cvss is not None:
                    break
        weaknesses = c.get("weaknesses") or []
        cwe = None
        if weaknesses and isinstance(weaknesses[0], dict):
            desc = weaknesses[0].get("description") or []
            if desc and isinstance(desc[0], dict):
                cwe = desc[0].get("value")
        out[cve] = {
            "cvss": cvss,
            "cwe": cwe,
            "published": c.get("published"),
            "lastModified": c.get("lastModified"),
        }
    return out


def infer_attack_kind(value: str | None) -> str:
    t = (value or "").lower()
    if "ransom" in t:
        return "ransomware"
    if "phish" in t:
        return "phishing / social engineering"
    if "credential" in t or "stealer" in t:
        return "credential theft"
    if "supply" in t or "dependency" in t:
        return "supply chain compromise"
    if "ddos" in t or "dos" in t:
        return "ddos"
    if "botnet" in t or "c2" in t or "command and control" in t:
        return "botnet c2"
    if "wiper" in t or "destructive" in t:
        return "wiper / destructive malware"
    if "cloud" in t or "iam" in t:
        return "cloud account / iam abuse"
    if "zero-day" in t or "0day" in t or "zero day" in t:
        return "zero-day exploitation"
    if "web" in t or "exploit" in t or "api" in t or "injection" in t:
        return "web/api exploitation"
    return "other / unclassified"


ATTACK_KIND_TO_MITRE: dict[str, dict[str, str]] = {
    "phishing / social engineering": {
        "attackTactic": "Initial Access",
        "attackTechniqueId": "T1566",
        "attackTechniqueName": "Phishing",
    },
    "ransomware": {
        "attackTactic": "Impact",
        "attackTechniqueId": "T1486",
        "attackTechniqueName": "Data Encrypted for Impact",
    },
    "credential theft": {
        "attackTactic": "Credential Access",
        "attackTechniqueId": "T1003",
        "attackTechniqueName": "OS Credential Dumping",
    },
    "supply chain compromise": {
        "attackTactic": "Initial Access",
        "attackTechniqueId": "T1195",
        "attackTechniqueName": "Supply Chain Compromise",
    },
    "ddos": {
        "attackTactic": "Impact",
        "attackTechniqueId": "T1498",
        "attackTechniqueName": "Network Denial of Service",
    },
    "botnet c2": {
        "attackTactic": "Command and Control",
        "attackTechniqueId": "T1071",
        "attackTechniqueName": "Application Layer Protocol",
    },
    "cloud account / iam abuse": {
        "attackTactic": "Privilege Escalation",
        "attackTechniqueId": "T1098",
        "attackTechniqueName": "Account Manipulation",
    },
    "zero-day exploitation": {
        "attackTactic": "Execution",
        "attackTechniqueId": "T1203",
        "attackTechniqueName": "Exploitation for Client Execution",
    },
    "known-exploited-vulnerability": {
        "attackTactic": "Initial Access",
        "attackTechniqueId": "T1190",
        "attackTechniqueName": "Exploit Public-Facing Application",
    },
    "web/api exploitation": {
        "attackTactic": "Initial Access",
        "attackTechniqueId": "T1190",
        "attackTechniqueName": "Exploit Public-Facing Application",
    },
    "business email compromise": {
        "attackTactic": "Initial Access",
        "attackTechniqueId": "T1566",
        "attackTechniqueName": "Phishing",
    },
    "insider threat": {
        "attackTactic": "Collection",
        "attackTechniqueId": "T1530",
        "attackTechniqueName": "Data from Cloud Storage Object",
    },
}


def apply_attack_taxonomy(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for e in events:
        kind = infer_attack_kind(str(e.get("attackKind") or e.get("type")))
        mapping = ATTACK_KIND_TO_MITRE.get(kind)
        if not mapping:
            out.append(e)
            continue
        enriched = {**e, **mapping}
        out.append(enriched)
    return out


async def fetch_threatfox(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    url = "https://threatfox-api.abuse.ch/api/v1/"
    rows: list[dict[str, Any]] = []
    for days in (3, 7, 14, 30):
        payload = {"query": "get_iocs", "days": days}
        data = (await client.post(url, json=payload, timeout=20)).json()
        if data.get("query_status") not in {"ok", "no_result"}:
            continue
        candidate = [r for r in data.get("data", [])[:MAX_THREATFOX_ROWS] if isinstance(r, dict)]
        if candidate:
            rows = candidate
            break
    if not rows:
        # Public export fallback when API query is unavailable.
        fallback_urls = [
            "https://threatfox.abuse.ch/export/json/recent/",
            "https://threatfox.abuse.ch/export/json/full/",
        ]
        for endpoint in fallback_urls:
            try:
                data = (await client.get(endpoint, timeout=25)).json()
            except Exception:
                continue
            if isinstance(data, dict):
                candidate = [r for r in data.get("data", [])[:MAX_THREATFOX_ROWS] if isinstance(r, dict)]
            elif isinstance(data, list):
                candidate = [r for r in data[:MAX_THREATFOX_ROWS] if isinstance(r, dict)]
            else:
                candidate = []
            if candidate:
                rows = candidate
                break
    if not rows:
        return []
    ip_iocs = [r.get("ioc") for r in rows if is_ipv4(r.get("ioc"))]
    geo_by_ip = await geolocate_ips_ip_api(client, [ip for ip in ip_iocs if isinstance(ip, str)])

    out = []
    for ioc in rows:
        cc = (ioc.get("country_code") or "").upper()
        ioc_value = ioc.get("ioc")
        lat = None
        lon = None
        country = cc or "UNK"
        location_quality = "country-centroid (approximate)"

        if is_ipv4(ioc_value) and ioc_value in geo_by_ip:
            g = geo_by_ip[ioc_value]
            lat = g.get("lat")
            lon = g.get("lon")
            country = g.get("country") or country
            location_quality = "ip-geolocated (approximate)"
        elif cc in COUNTRY_CENTROIDS:
            lat, lon = COUNTRY_CENTROIDS[cc]
            country = cc
            location_quality = "country-centroid (approximate)"
        else:
            # Skip non-geolocatable IOCs; map should only show meaningful coordinates.
            continue

        first_seen = ioc.get("first_seen") or ioc.get("ioc_first_seen") or ioc.get("date_added")
        out.append(
            {
                "id": f"tf-{ioc.get('id', ioc.get('ioc'))}",
                "country": country,
                "lat": lat,
                "lon": lon,
                "type": ioc.get("malware", "IOC"),
                "attackKind": ioc.get("threat_type_desc") or ioc.get("threat_type") or "malicious IOC",
                "source": "threatfox",
                "ip": ioc_value if is_ipv4(ioc_value) else None,
                "firstSeen": first_seen,
                "locationQuality": location_quality,
                "confidence": normalize_score(float(ioc.get("confidence_level", 50)), 0, 100),
                "assetCriticality": 3,
                "hoursAgo": hours_since_iso8601(first_seen, fallback=6),
                "kev": 0,
                "epss": 0.0,
            }
        )
    return out


async def fetch_openphish(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    # OpenPhish feed is URL-focused; resolve URL hosts to IP for geolocated phishing hotspots.
    url = "https://openphish.com/feed.txt"
    try:
        text = (await client.get(url, timeout=20)).text
    except Exception:
        return []
    rows = [line.strip() for line in text.splitlines() if line.strip() and line.strip().startswith("http")]
    sample = rows[:MAX_OPENPHISH_ROWS]
    host_to_ip = await resolve_url_hosts_to_ipv4(sample)
    geo = await geolocate_ips_ip_api(client, list(host_to_ip.values()))
    out: list[dict[str, Any]] = []
    for i, u in enumerate(sample):
        host = safe_url_host(u)
        ip = host_to_ip.get(host) if host else None
        g = geo.get(ip) if ip else None
        out.append(
            {
                "id": f"openphish-{i}",
                "country": g.get("country", "GLOBAL") if g else "GLOBAL",
                "lat": g.get("lat") if g else None,
                "lon": g.get("lon") if g else None,
                "type": "OpenPhish URL",
                "attackKind": "phishing / social engineering",
                "source": "openphish+dns+ip-api" if g else "openphish",
                "ip": ip,
                "ioc": u,
                "firstSeen": None,
                "locationQuality": "ip-geolocated (approximate)" if g else "not-geolocated",
                "confidence": 0.76,
                "assetCriticality": 3,
                "hoursAgo": 6,
                "kev": 0,
                "epss": 0.0,
            }
        )
    return out


async def fetch_phishtank(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    # Community phishing feed; resolve URL hosts to IP for geolocated phishing hotspots.
    rows: list[dict[str, Any]] = []
    json_candidates = [
        "https://data.phishtank.com/data/online-valid.json",
        "http://data.phishtank.com/data/online-valid.json",
    ]
    for url in json_candidates:
        try:
            data = (await client.get(url, timeout=25)).json()
        except Exception:
            continue
        if isinstance(data, list):
            rows = [r for r in data[:MAX_PHISHTANK_ROWS] if isinstance(r, dict)]
        if rows:
            break
    if not rows:
        # Fallback: public CSV feed when JSON endpoint is unavailable/blocked.
        csv_candidates = [
            "https://data.phishtank.com/data/online-valid.csv",
            "http://data.phishtank.com/data/online-valid.csv",
        ]
        for url in csv_candidates:
            try:
                text = (await client.get(url, timeout=25)).text
            except Exception:
                continue
            if not text or "," not in text:
                continue
            try:
                reader = csv.DictReader(io.StringIO(text))
                rows = [r for _, r in zip(range(MAX_PHISHTANK_ROWS), reader) if isinstance(r, dict)]
            except Exception:
                rows = []
            if rows:
                break
    if not rows:
        return []

    urls = [str(r.get("url") or "") for r in rows if r.get("url")]
    host_to_ip = await resolve_url_hosts_to_ipv4(urls)
    geo = await geolocate_ips_ip_api(client, list(host_to_ip.values()))
    out: list[dict[str, Any]] = []
    for i, r in enumerate(rows):
        submitted = r.get("submission_time")
        verified = r.get("verification_time")
        target = r.get("target") or "phishing"
        u = r.get("url")
        host = safe_url_host(u)
        ip = host_to_ip.get(host) if host else None
        g = geo.get(ip) if ip else None
        out.append(
            {
                "id": f"phishtank-{r.get('phish_id', i)}",
                "country": g.get("country", "GLOBAL") if g else "GLOBAL",
                "lat": g.get("lat") if g else None,
                "lon": g.get("lon") if g else None,
                "type": f"PhishTank {target}",
                "attackKind": "phishing / social engineering",
                "source": "phishtank+dns+ip-api" if g else "phishtank",
                "ip": ip,
                "ioc": u,
                "firstSeen": submitted or verified,
                "locationQuality": "ip-geolocated (approximate)" if g else "not-geolocated",
                "confidence": 0.74,
                "assetCriticality": 3,
                "hoursAgo": hours_since_iso8601(submitted or verified, fallback=9),
                "kev": 0,
                "epss": 0.0,
            }
        )
    return out


async def fetch_urlhaus(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    # URLhaus recent URLs with optional IP host geolocation.
    endpoint_candidates = [
        ("POST", "https://urlhaus-api.abuse.ch/v1/urls/recent/"),
        ("GET", "https://urlhaus-api.abuse.ch/v1/urls/recent/"),
    ]
    rows: list[dict[str, Any]] = []
    for method, endpoint in endpoint_candidates:
        try:
            if method == "POST":
                data = (await client.post(endpoint, data={}, timeout=25)).json()
            else:
                data = (await client.get(endpoint, timeout=25)).json()
        except Exception:
            continue
        if isinstance(data, dict):
            rows = [r for r in data.get("urls", [])[:MAX_URLHAUS_ROWS] if isinstance(r, dict)]
        elif isinstance(data, list):
            rows = [r for r in data[:MAX_URLHAUS_ROWS] if isinstance(r, dict)]
        if rows:
            break
    if not rows:
        # Fallback: parse recent CSV export.
        csv_candidates = [
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "https://urlhaus.abuse.ch/downloads/csv/",
        ]
        for endpoint in csv_candidates:
            try:
                text = (await client.get(endpoint, timeout=25)).text
            except Exception:
                continue
            if not text:
                continue
            parsed: list[dict[str, Any]] = []
            try:
                # URLhaus CSV has comment lines prefixed with '#'.
                filtered = "\n".join([ln for ln in text.splitlines() if ln and not ln.lstrip().startswith("#")])
                reader = csv.reader(io.StringIO(filtered))
                for row in reader:
                    if len(parsed) >= MAX_URLHAUS_ROWS:
                        break
                    if len(row) < 8:
                        continue
                    parsed.append(
                        {
                            "id": row[0].strip(),
                            "date_added": row[1].strip(),
                            "url": row[2].strip(),
                            "url_status": row[3].strip(),
                            "threat": row[5].strip(),
                            "host": row[6].strip(),
                            "tags": [t.strip() for t in row[7].split(",") if t.strip()],
                        }
                    )
            except Exception:
                parsed = []
            if parsed:
                rows = parsed
                break
    if not rows:
        return []
    ip_hosts = [r.get("host") for r in rows if is_ipv4(r.get("host"))]
    domain_hosts = [str(r.get("host")).strip().lower() for r in rows if isinstance(r.get("host"), str) and not is_ipv4(r.get("host"))]
    resolved_domains = await resolve_hosts_to_ipv4(domain_hosts)
    geo = await geolocate_ips_ip_api(client, [ip for ip in ip_hosts if isinstance(ip, str)] + list(resolved_domains.values()))

    out: list[dict[str, Any]] = []
    for r in rows:
        host = r.get("host")
        tags = " ".join([str(x) for x in (r.get("tags") or [])])
        family = r.get("threat") or r.get("url_status") or "urlhaus-ioc"
        attack_kind = infer_attack_kind(f"{family} {tags}")
        lat = None
        lon = None
        country = "GLOBAL"
        location_quality = "not-geolocated"
        ip = None
        if is_ipv4(host):
            ip = host
        elif isinstance(host, str):
            ip = resolved_domains.get(host.strip().lower())
        if ip and ip in geo:
            g = geo[ip]
            lat = g.get("lat")
            lon = g.get("lon")
            country = g.get("country", "UNK")
            location_quality = "ip-geolocated (approximate)"
        out.append(
            {
                "id": f"urlhaus-{r.get('id', r.get('url_id', len(out)))}",
                "country": country,
                "lat": lat,
                "lon": lon,
                "type": str(family),
                "attackKind": attack_kind,
                "source": "urlhaus+dns+ip-api" if ip else "urlhaus",
                "ip": ip,
                "ioc": r.get("url"),
                "firstSeen": r.get("date_added"),
                "locationQuality": location_quality,
                "confidence": 0.7,
                "assetCriticality": 3,
                "hoursAgo": hours_since_iso8601(r.get("date_added"), fallback=10),
                "kev": 0,
                "epss": 0.0,
            }
        )
    return out


async def fetch_malwarebazaar(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    # MalwareBazaar recent sample telemetry (non-geolocated alert intelligence).
    endpoint = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": ABUSECH_API_KEY} if ABUSECH_API_KEY else {}
    rows: list[dict[str, Any]] = []
    payload_candidates = [
        {"query": "get_recent", "selector": "time"},
        {"query": "get_recent"},
    ]
    for payload in payload_candidates:
        if not reserve_abusech_request():
            raise RuntimeError("daily_limit")
        try:
            data = (await client.post(endpoint, data=payload, headers=headers, timeout=25)).json()
        except Exception:
            continue
        if data.get("query_status") not in {"ok", "no_result"}:
            continue
        rows = [r for r in data.get("data", []) if isinstance(r, dict)][:MAX_MALWAREBAZAAR_ROWS]
        if rows:
            break
    if not rows:
        return []

    out: list[dict[str, Any]] = []
    for i, r in enumerate(rows):
        family = r.get("signature") or r.get("file_type_mime") or r.get("file_type") or "malware"
        tags = " ".join([str(t) for t in (r.get("tags") or []) if isinstance(t, str)]).strip()
        text = f"{family} {tags}"
        first_seen = r.get("first_seen")
        out.append(
            {
                "id": f"malwarebazaar-{r.get('sha256_hash', i)}",
                "country": "GLOBAL",
                "lat": None,
                "lon": None,
                "type": f"MalwareBazaar {family}",
                "attackKind": infer_attack_kind(text),
                "source": "malwarebazaar",
                "ioc": r.get("sha256_hash") or r.get("sha3_384_hash"),
                "firstSeen": first_seen,
                "locationQuality": "not-geolocated",
                "confidence": 0.73,
                "assetCriticality": 3,
                "hoursAgo": hours_since_iso8601(first_seen, fallback=12),
                "kev": 0,
                "epss": 0.0,
            }
        )
    return out


async def fetch_depsdev_supply_chain(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    # deps.dev v3 package metadata/advisory coverage for supply-chain visibility.
    packages = [
        ("npm", "lodash"),
        ("npm", "ua-parser-js"),
        ("npm", "event-stream"),
        ("npm", "minimist"),
        ("npm", "axios"),
        ("npm", "serialize-javascript"),
        ("npm", "node-forge"),
        ("npm", "json5"),
        ("pypi", "urllib3"),
        ("pypi", "requests"),
        ("pypi", "jinja2"),
        ("pypi", "pillow"),
        ("pypi", "cryptography"),
        ("pypi", "django"),
        ("pypi", "flask"),
        ("maven", "org.apache.logging.log4j:log4j-core"),
        ("maven", "org.springframework:spring-core"),
        ("maven", "commons-io:commons-io"),
        ("maven", "org.yaml:snakeyaml"),
        ("maven", "com.fasterxml.jackson.core:jackson-databind"),
        ("go", "github.com/gin-gonic/gin"),
        ("go", "golang.org/x/crypto"),
        ("go", "github.com/hashicorp/go-getter"),
        ("go", "gopkg.in/yaml.v2"),
    ]
    out: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for system, pkg in packages:
        if len(out) >= MAX_DEPSDEV_EVENTS:
            break
        if not reserve_depsdev_request():
            raise RuntimeError("daily_limit")
        url = f"https://api.deps.dev/v3/systems/{quote(system)}/packages/{quote(pkg, safe='')}"
        try:
            data = (await client.get(url, timeout=20)).json()
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        versions = data.get("versions") if isinstance(data.get("versions"), list) else []
        version_rows = [v for v in versions if isinstance(v, dict)]
        if not version_rows:
            continue
        preferred = next((v for v in version_rows if v.get("isDefault")), None) or version_rows[-1]
        version_key = str(preferred.get("versionKey") or preferred.get("version") or "")
        if not version_key:
            continue

        advisories: list[Any] = []
        if isinstance(preferred.get("advisoryKeys"), list):
            advisories = preferred.get("advisoryKeys", [])
        elif isinstance(preferred.get("advisories"), list):
            advisories = preferred.get("advisories", [])

        if not advisories:
            if not reserve_depsdev_request():
                raise RuntimeError("daily_limit")
            vurl = (
                f"https://api.deps.dev/v3/systems/{quote(system)}/packages/{quote(pkg, safe='')}"
                f"/versions/{quote(version_key, safe='')}"
            )
            try:
                vdata = (await client.get(vurl, timeout=20)).json()
            except Exception:
                vdata = {}
            if isinstance(vdata, dict):
                if isinstance(vdata.get("advisoryKeys"), list):
                    advisories = vdata.get("advisoryKeys", [])
                elif isinstance(vdata.get("advisories"), list):
                    advisories = vdata.get("advisories", [])

        for i, adv in enumerate(advisories[:8]):
            if isinstance(adv, dict):
                aid = str(
                    adv.get("id")
                    or adv.get("sourceID")
                    or adv.get("displayName")
                    or adv.get("name")
                    or ""
                ).strip()
            else:
                aid = str(adv).strip()
            if not aid:
                aid = f"{system}-{pkg}-{version_key}-{i}"
            if aid in seen_ids:
                continue
            seen_ids.add(aid)
            out.append(
                {
                    "id": f"depsdev-{aid}",
                    "country": "GLOBAL",
                    "lat": None,
                    "lon": None,
                    "type": f"deps.dev advisory {pkg}",
                    "attackKind": "supply chain compromise",
                    "source": "deps.dev",
                    "ioc": f"{system}/{pkg}@{version_key}",
                    "firstSeen": None,
                    "locationQuality": "not-geolocated",
                    "confidence": 0.71,
                    "assetCriticality": 3,
                    "hoursAgo": 24,
                    "kev": 0,
                    "epss": 0.0,
                }
            )
            if len(out) >= MAX_DEPSDEV_EVENTS:
                break
    return out


async def fetch_osv_supply_chain(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    packages = [
        ("Maven", "org.apache.logging.log4j:log4j-core"),
        ("Maven", "com.fasterxml.jackson.core:jackson-databind"),
        ("Maven", "org.springframework:spring-core"),
        ("PyPI", "urllib3"),
        ("PyPI", "jinja2"),
        ("PyPI", "django"),
        ("npm", "lodash"),
        ("npm", "axios"),
        ("npm", "minimist"),
        ("Go", "golang.org/x/crypto"),
    ]
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    endpoint = "https://api.osv.dev/v1/query"
    for eco, name in packages:
        if len(out) >= MAX_OSV_EVENTS:
            break
        if not reserve_osv_request():
            raise RuntimeError("daily_limit")
        body = {"package": {"ecosystem": eco, "name": name}}
        try:
            data = (await client.post(endpoint, json=body, timeout=20)).json()
        except Exception:
            continue
        vulns = data.get("vulns", []) if isinstance(data, dict) and isinstance(data.get("vulns"), list) else []
        for i, v in enumerate(vulns[:8]):
            vid = str(v.get("id") or f"{eco}-{name}-{i}")
            if vid in seen:
                continue
            seen.add(vid)
            out.append(
                {
                    "id": f"osv-{vid}",
                    "country": "GLOBAL",
                    "lat": None,
                    "lon": None,
                    "type": f"OSV advisory {name}",
                    "attackKind": "supply chain compromise",
                    "source": "osv",
                    "ioc": f"{eco}/{name}#{vid}",
                    "firstSeen": None,
                    "locationQuality": "not-geolocated",
                    "confidence": 0.74,
                    "assetCriticality": 3,
                    "hoursAgo": 24,
                    "kev": 0,
                    "epss": 0.0,
                }
            )
            if len(out) >= MAX_OSV_EVENTS:
                break
    return out


async def fetch_pulsedive(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    # Pulsedive IOC feed; supports multiple categories and both geolocated/non-geolocated events.
    global PULSEDIVE_COOLDOWN_UNTIL
    now = time.time()
    if now < PULSEDIVE_COOLDOWN_UNTIL:
        raise RuntimeError("cooldown")
    api_rows: list[dict[str, Any]] = []
    base_params = {"limit": str(min(MAX_PULSEDIVE_ROWS, 80))}
    key_part = {"key": PULSEDIVE_API_KEY} if PULSEDIVE_API_KEY else {}
    candidates = [("https://pulsedive.com/api/explore.php", {"type": "indicator", "risk": "high", **base_params, **key_part})]
    if PULSEDIVE_API_KEY:
        candidates.extend(
            [
                ("https://pulsedive.com/api/explore.php", {"type": "indicator", **base_params, **key_part}),
                ("https://pulsedive.com/api/explore.php", {"indicator": "all", "risk": "high", **base_params, **key_part}),
                ("https://pulsedive.com/api/info.php", {"type": "indicator", "risk": "high", **base_params, **key_part}),
            ]
        )
    saw_quota = False
    saw_client_error = False
    for url, req_params in candidates:
        if not reserve_pulsedive_request():
            raise RuntimeError("daily_limit")
        try:
            resp = await client.get(url, params=req_params, timeout=25)
            text = resp.text or ""
            debug_feed("pulsedive", f"url={url} status={resp.status_code} bytes={len(text)}")
            if resp.status_code == 429:
                saw_quota = True
                continue
            if resp.status_code >= 400:
                saw_client_error = True
                continue
            data = resp.json()
        except Exception as exc:
            debug_feed("pulsedive", f"url={url} error={type(exc).__name__}")
            continue
        if isinstance(data, dict):
            error_blob = " ".join(
                [
                    str(data.get("error") or ""),
                    str(data.get("message") or ""),
                    str(data.get("status") or ""),
                ]
            ).lower()
            if "quota" in error_blob or "rate limit" in error_blob or "too many" in error_blob or "limit reached" in error_blob:
                saw_quota = True
                continue
            if isinstance(data.get("results"), list):
                api_rows = [r for r in data.get("results", []) if isinstance(r, dict)][:MAX_PULSEDIVE_ROWS]
            elif isinstance(data.get("data"), list):
                api_rows = [r for r in data.get("data", []) if isinstance(r, dict)][:MAX_PULSEDIVE_ROWS]
        elif isinstance(data, list):
            api_rows = [r for r in data if isinstance(r, dict)][:MAX_PULSEDIVE_ROWS]
            debug_feed("pulsedive", f"url={url} list_rows={len(api_rows)}")
        else:
            debug_feed("pulsedive", f"url={url} non-dict json type={type(data).__name__}")
        if isinstance(data, dict):
            debug_feed(
                "pulsedive",
                f"url={url} keys={list(data.keys())[:8]} results={len(data.get('results') or []) if isinstance(data.get('results'), list) else 'n/a'} data={len(data.get('data') or []) if isinstance(data.get('data'), list) else 'n/a'}",
            )
        if api_rows:
            break
    if not api_rows and saw_quota:
        # Back off 30 minutes to avoid hammering a rate-limited API.
        PULSEDIVE_COOLDOWN_UNTIL = time.time() + 1800
        raise RuntimeError("quota")
    if not api_rows and saw_client_error:
        raise RuntimeError("client_error")
    rows = api_rows
    ips = [r.get("indicator") for r in rows if str(r.get("type", "")).lower() in {"ip", "ipv4"} and is_ipv4(r.get("indicator"))]
    domain_candidates: list[str] = []
    for r in rows:
        ind = r.get("indicator")
        ind_type = str(r.get("type", "")).lower()
        if not isinstance(ind, str):
            continue
        if ind_type in {"domain", "hostname"}:
            domain_candidates.append(ind.strip().lower())
        elif ind_type in {"url", "uri"}:
            host = safe_url_host(ind)
            if host:
                domain_candidates.append(host)
    resolved_domains = await resolve_hosts_to_ipv4(domain_candidates)
    geo = await geolocate_ips_ip_api(client, [ip for ip in ips if isinstance(ip, str)] + list(resolved_domains.values()))
    out: list[dict[str, Any]] = []
    for i, r in enumerate(rows):
        ind = r.get("indicator")
        ind_type = str(r.get("type", "")).lower()
        threat = r.get("threat") or r.get("category") or r.get("risk") or ind_type or "ioc"
        first_seen = r.get("stamp_seen") or r.get("stamp_added")
        attack_kind = infer_attack_kind(str(threat))
        ip = None
        if ind_type in {"ip", "ipv4"} and is_ipv4(ind):
            ip = ind
        elif ind_type in {"domain", "hostname"} and isinstance(ind, str):
            ip = resolved_domains.get(ind.strip().lower())
        elif ind_type in {"url", "uri"} and isinstance(ind, str):
            host = safe_url_host(ind)
            if host:
                ip = resolved_domains.get(host)
        if ip and ip in geo:
            g = geo[ip]
            out.append(
                {
                    "id": f"pulsedive-ip-{ip}-{i}",
                    "country": g.get("country", "UNK"),
                    "lat": g.get("lat"),
                    "lon": g.get("lon"),
                    "type": f"Pulsedive {threat}",
                    "attackKind": attack_kind,
                    "source": "pulsedive+dns+ip-api",
                    "ip": ip,
                    "ioc": ind,
                    "firstSeen": first_seen,
                    "locationQuality": "ip-geolocated (approximate)",
                    "confidence": 0.69,
                    "assetCriticality": 3,
                    "hoursAgo": hours_since_iso8601(first_seen, fallback=10),
                    "kev": 0,
                    "epss": 0.0,
                }
            )
        else:
            out.append(
                {
                    "id": f"pulsedive-{i}",
                    "country": "GLOBAL",
                    "lat": None,
                    "lon": None,
                    "type": f"Pulsedive {threat}",
                    "attackKind": attack_kind,
                    "source": "pulsedive",
                    "ioc": ind,
                    "firstSeen": first_seen,
                    "locationQuality": "not-geolocated",
                    "confidence": 0.66,
                    "assetCriticality": 3,
                    "hoursAgo": hours_since_iso8601(first_seen, fallback=10),
                    "kev": 0,
                    "epss": 0.0,
                }
            )
    return out


async def fetch_otx(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    if not OTX_API_KEY:
        return []
    # Pull recent subscribed pulses and extract IPv4 indicators for map events.
    endpoint = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    try:
        data = (await client.get(endpoint, headers={"X-OTX-API-KEY": OTX_API_KEY}, timeout=25)).json()
    except Exception:
        return []
    pulses = [p for p in data.get("results", [])[:MAX_OTX_PULSES] if isinstance(p, dict)]
    ip_rows: list[tuple[str, str, str | None]] = []
    for p in pulses:
        name = str(p.get("name") or "OTX pulse")
        created = p.get("created")
        indicators = p.get("indicators") or []
        for ind in indicators:
            if not isinstance(ind, dict):
                continue
            val = ind.get("indicator")
            if is_ipv4(val):
                ip_rows.append((val, name, created))
                if len(ip_rows) >= MAX_OTX_IP_ROWS:
                    break
        if len(ip_rows) >= MAX_OTX_IP_ROWS:
            break
    geo = await geolocate_ips_ip_api(client, [ip for ip, _, _ in ip_rows])
    out: list[dict[str, Any]] = []
    for ip, pulse_name, created in ip_rows:
        if ip not in geo:
            continue
        g = geo[ip]
        attack_kind = infer_attack_kind(pulse_name)
        out.append(
            {
                "id": f"otx-{ip}-{len(out)}",
                "country": g.get("country", "UNK"),
                "lat": g.get("lat"),
                "lon": g.get("lon"),
                "type": "OTX IOC",
                "attackKind": attack_kind,
                "source": "otx",
                "ip": ip,
                "firstSeen": created,
                "locationQuality": "ip-geolocated (approximate)",
                "confidence": 0.68,
                "assetCriticality": 3,
                "hoursAgo": hours_since_iso8601(created, fallback=18),
                "kev": 0,
                "epss": 0.0,
            }
        )
    return out


async def fetch_circl_recent(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    # CIRCL recent CVE feed as alert intelligence (non-geolocated).
    url = "https://cve.circl.lu/api/last"
    try:
        data = (await client.get(url, timeout=25)).json()
    except Exception:
        return []
    rows = [r for r in data[:MAX_CIRCL_ROWS] if isinstance(r, dict)] if isinstance(data, list) else []
    out: list[dict[str, Any]] = []
    for i, r in enumerate(rows):
        cve = r.get("id") or r.get("cve") or f"circl-{i}"
        summary = r.get("summary") or r.get("Published") or "recent vulnerability"
        published = r.get("Published") or r.get("PublishedDate")
        out.append(
            {
                "id": f"circl-{cve}",
                "country": "GLOBAL",
                "lat": None,
                "lon": None,
                "type": f"CIRCL {cve}",
                "attackKind": "known-exploited-vulnerability" if "exploit" in str(summary).lower() else "web/api exploitation",
                "source": "circl-cve",
                "ioc": cve,
                "firstSeen": published,
                "locationQuality": "not-geolocated",
                "confidence": 0.72,
                "assetCriticality": 4,
                "hoursAgo": hours_since_iso8601(published, fallback=14),
                "kev": 0,
                "epss": 0.0,
            }
        )
    return out


async def fetch_cisa_alerts(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    # CISA advisories RSS/XML as live non-geolocated alert intelligence.
    global CISA_COOLDOWN_UNTIL
    if time.time() < CISA_COOLDOWN_UNTIL:
        raise RuntimeError("cooldown")
    endpoint_candidates = [
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "https://www.cisa.gov/news-events/cybersecurity-advisories.xml",
        "https://www.cisa.gov/cybersecurity-advisories.xml",
        "https://www.cisa.gov/sites/default/files/feeds/cybersecurity-advisories.xml",
        "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "https://www.cisa.gov/uscert/ncas/current-activity.xml",
        "https://www.cisa.gov/uscert/ncas/analysis-reports.xml",
    ]
    xml_text = None
    saw_forbidden = False
    for url in endpoint_candidates:
        try:
            resp = await client.get(url, timeout=25)
            if resp.status_code == 403:
                saw_forbidden = True
                continue
            xml_text = resp.text
        except Exception:
            continue
        if xml_text and "<item" in xml_text:
            break
        if xml_text and "<entry" in xml_text:
            break
    if not xml_text:
        if saw_forbidden:
            CISA_COOLDOWN_UNTIL = time.time() + 1800
            raise RuntimeError("forbidden")
        return []

    out: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return []
    items = root.findall(".//item") or root.findall(".//{*}item")
    if not items:
        # Atom fallback
        items = root.findall(".//{http://www.w3.org/2005/Atom}entry") or root.findall(".//{*}entry")
    for i, item in enumerate(items[:MAX_CISA_ALERT_ROWS]):
        title = (
            item.findtext("title")
            or item.findtext("{*}title")
            or item.findtext("{http://www.w3.org/2005/Atom}title")
            or ""
        ).strip()
        desc = (
            item.findtext("description")
            or item.findtext("{*}description")
            or item.findtext("summary")
            or item.findtext("{*}summary")
            or item.findtext("{http://www.w3.org/2005/Atom}summary")
            or ""
        ).strip()
        pub = (
            item.findtext("pubDate")
            or item.findtext("{*}pubDate")
            or item.findtext("published")
            or item.findtext("{*}published")
            or item.findtext("updated")
            or item.findtext("{*}updated")
            or item.findtext("{http://www.w3.org/2005/Atom}published")
            or item.findtext("{http://www.w3.org/2005/Atom}updated")
            or ""
        ).strip()
        link = (item.findtext("link") or item.findtext("{*}link") or "").strip()
        if not link:
            atom_link = item.find("{http://www.w3.org/2005/Atom}link") or item.find("{*}link")
            if atom_link is not None:
                link = str(atom_link.attrib.get("href") or "").strip()
        text = f"{title} {desc}"
        attack_kind = infer_attack_kind(text)
        # Heuristic boosts for glossary coverage on advisory terms.
        low = text.lower()
        if "business email compromise" in low or "bec" in low:
            attack_kind = "business email compromise"
        elif "insider" in low:
            attack_kind = "insider threat"
        elif "credential" in low:
            attack_kind = "credential theft"
        elif "supply chain" in low:
            attack_kind = "supply chain compromise"
        elif "cloud" in low or "iam" in low or "identity" in low:
            attack_kind = "cloud account / iam abuse"

        out.append(
            {
                "id": f"cisa-adv-{i}",
                "country": "GLOBAL",
                "lat": None,
                "lon": None,
                "type": f"CISA Advisory {title[:120]}",
                "attackKind": attack_kind,
                "source": "cisa-advisories",
                "ioc": link or title,
                "firstSeen": pub or None,
                "locationQuality": "not-geolocated",
                "confidence": 0.75,
                "assetCriticality": 4,
                "hoursAgo": hours_since_iso8601(pub, fallback=20),
                "kev": 0,
                "epss": 0.0,
            }
        )
    return out


async def fetch_urlscan_recent(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    # Free-tier friendly: small pull of recent suspicious/malicious scans.
    q = quote("(verdicts.overall.malicious:1 OR verdicts.urlscan.malicious:1) AND date:>now-3d")
    url = f"https://urlscan.io/api/v1/search/?q={q}&size={MAX_URLSCAN_ROWS}"
    headers = {"API-Key": URLSCAN_API_KEY} if URLSCAN_API_KEY else {}
    try:
        data = (await client.get(url, headers=headers, timeout=25)).json()
    except Exception:
        return []
    rows = data.get("results") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return []
    out: list[dict[str, Any]] = []
    for i, r in enumerate(rows[:MAX_URLSCAN_ROWS]):
        if not isinstance(r, dict):
            continue
        page = r.get("page") if isinstance(r.get("page"), dict) else {}
        task = r.get("task") if isinstance(r.get("task"), dict) else {}
        country = country_code_from_value(page.get("country"))
        if not country or country not in COUNTRY_CENTROIDS:
            continue
        lat, lon = COUNTRY_CENTROIDS[country]
        seen = task.get("time") or r.get("indexedAt")
        domain = page.get("domain") or page.get("ip") or page.get("url") or "urlscan"
        out.append(
            {
                "id": f"urlscan-{i}-{domain}",
                "country": country,
                "lat": lat,
                "lon": lon,
                "type": "urlscan suspicious web activity",
                "attackKind": "web/api exploitation",
                "source": "urlscan",
                "ioc": domain,
                "firstSeen": seen,
                "locationQuality": "scan-country-centroid (approximate)",
                "confidence": 0.68,
                "assetCriticality": 3,
                "hoursAgo": hours_since_iso8601(seen, fallback=12),
                "kev": 0,
                "epss": 0.0,
            }
        )
    return out


async def fetch_shodan_activity(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    if not SHODAN_API_KEY:
        return []
    # Keep query/rows small on free plan to avoid exhausting credits.
    url = "https://api.shodan.io/shodan/host/search"
    params = {"key": SHODAN_API_KEY, "query": "product:rdp OR product:ssh OR tag:ics", "page": 1}
    try:
        data = (await client.get(url, params=params, timeout=25)).json()
    except Exception:
        return []
    rows = data.get("matches") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return []
    out: list[dict[str, Any]] = []
    for i, r in enumerate(rows[:MAX_SHODAN_ROWS]):
        if not isinstance(r, dict):
            continue
        loc = r.get("location") if isinstance(r.get("location"), dict) else {}
        lat = loc.get("latitude")
        lon = loc.get("longitude")
        cc = country_code_from_value(loc.get("country_code") or loc.get("country_name"))
        if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
            if not cc or cc not in COUNTRY_CENTROIDS:
                continue
            lat, lon = COUNTRY_CENTROIDS[cc]
        if not cc:
            cc = "UNK"
        ts = r.get("timestamp")
        port = r.get("port")
        org = r.get("org") or r.get("isp") or "shodan-host"
        out.append(
            {
                "id": f"shodan-{i}-{r.get('ip_str') or org}",
                "country": cc,
                "lat": lat,
                "lon": lon,
                "type": f"Shodan exposed service {port or ''}".strip(),
                "attackKind": "web/api exploitation",
                "source": "shodan",
                "ip": r.get("ip_str"),
                "ioc": org,
                "firstSeen": ts,
                "locationQuality": "host-geolocated (approximate)",
                "confidence": 0.62,
                "assetCriticality": 3,
                "hoursAgo": hours_since_iso8601(ts, fallback=18),
                "kev": 0,
                "epss": 0.0,
            }
        )
    return out


async def fetch_censys_activity(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        return []
    url = "https://search.censys.io/api/v2/hosts/search"
    payload = {"q": "services.service_name: HTTP", "per_page": MAX_CENSYS_ROWS}
    try:
        res = await client.post(url, json=payload, auth=(CENSYS_API_ID, CENSYS_API_SECRET), timeout=25)
        data = res.json()
    except Exception:
        return []
    block = data.get("result") if isinstance(data, dict) else None
    rows = block.get("hits") if isinstance(block, dict) else None
    if not isinstance(rows, list):
        return []
    out: list[dict[str, Any]] = []
    for i, r in enumerate(rows[:MAX_CENSYS_ROWS]):
        if not isinstance(r, dict):
            continue
        loc = r.get("location") if isinstance(r.get("location"), dict) else {}
        cc = country_code_from_value(loc.get("country_code") or loc.get("country"))
        lat = loc.get("latitude")
        lon = loc.get("longitude")
        if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
            if not cc or cc not in COUNTRY_CENTROIDS:
                continue
            lat, lon = COUNTRY_CENTROIDS[cc]
        if not cc:
            cc = "UNK"
        ip = r.get("ip")
        out.append(
            {
                "id": f"censys-{i}-{ip or 'host'}",
                "country": cc,
                "lat": lat,
                "lon": lon,
                "type": "Censys exposed host telemetry",
                "attackKind": "web/api exploitation",
                "source": "censys",
                "ip": ip,
                "ioc": ip or "censys-host",
                "firstSeen": None,
                "locationQuality": "host-geolocated (approximate)",
                "confidence": 0.6,
                "assetCriticality": 3,
                "hoursAgo": 24,
                "kev": 0,
                "epss": 0.0,
            }
        )
    return out


def country_code_from_value(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    up = raw.upper()
    if len(up) == 2 and up in COUNTRY_CENTROIDS:
        return up
    by_name = {
        "UNITED STATES": "US",
        "USA": "US",
        "UNITED KINGDOM": "GB",
        "GREAT BRITAIN": "GB",
        "GERMANY": "DE",
        "FRANCE": "FR",
        "NETHERLANDS": "NL",
        "SWEDEN": "SE",
        "POLAND": "PL",
        "UKRAINE": "UA",
        "RUSSIA": "RU",
        "CHINA": "CN",
        "INDIA": "IN",
        "SINGAPORE": "SG",
        "JAPAN": "JP",
        "KOREA": "KR",
        "SOUTH KOREA": "KR",
        "BRAZIL": "BR",
        "MEXICO": "MX",
        "CANADA": "CA",
        "AUSTRALIA": "AU",
        "SPAIN": "ES",
        "ITALY": "IT",
    }
    return by_name.get(up)


async def fetch_ransomware_live(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    # Victim-post telemetry by country, mapped to country centroid.
    endpoint_candidates = [
        "https://api.ransomware.live/v2/recentposts",
        "https://api.ransomware.live/v2/posts",
        "https://api.ransomware.live/v2/recentvictims",
        "https://api.ransomware.live/v2/victims",
    ]
    rows: list[dict[str, Any]] = []
    for url in endpoint_candidates:
        try:
            data = (await client.get(url, timeout=25)).json()
        except Exception:
            continue
        if isinstance(data, list):
            rows = [r for r in data if isinstance(r, dict)]
        elif isinstance(data, dict) and isinstance(data.get("data"), list):
            rows = [r for r in data.get("data", []) if isinstance(r, dict)]
        if rows:
            break
    if not rows:
        return []

    out: list[dict[str, Any]] = []
    for i, r in enumerate(rows[:MAX_RANSOMWARE_LIVE_ROWS]):
        cc = country_code_from_value(
            r.get("country")
            or r.get("country_code")
            or r.get("location")
            or r.get("victim_country")
            or r.get("countryCode")
        )
        if not cc or cc not in COUNTRY_CENTROIDS:
            continue
        lat, lon = COUNTRY_CENTROIDS[cc]
        seen = r.get("discovered") or r.get("published") or r.get("post_date")
        group = r.get("group_name") or r.get("group") or "ransomware-group"
        victim = r.get("post_title") or r.get("victim") or "victim"
        out.append(
            {
                "id": f"ransomware-live-{i}",
                "country": cc,
                "lat": lat,
                "lon": lon,
                "type": f"Ransomware.live {group}",
                "attackKind": "ransomware",
                "source": "ransomware.live",
                "ioc": victim,
                "firstSeen": seen,
                "locationQuality": "victim-country-centroid (approximate)",
                "confidence": 0.73,
                "assetCriticality": 4,
                "hoursAgo": hours_since_iso8601(seen, fallback=18),
                "kev": 0,
                "epss": 0.0,
            }
        )
    return out


async def fetch_ddos_country_telemetry(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    # Cloudflare Radar telemetry; token-enabled endpoint first, then public candidates.
    endpoint_candidates = [
        # Cloudflare GraphQL endpoint (token only).
        "https://api.cloudflare.com/client/v4/graphql",
        "https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/origin",
        "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/origin",
        "https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/target",
        "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/target",
        "https://radar.cloudflare.com/api/v2/attacks/layer3/top/locations",
        "https://radar.cloudflare.com/api/v2/attacks/layer7/top/locations",
        # NETSCOUT Horizon-style candidates (best-effort; may require API/allowlist).
        "https://horizon.netscout.com/api/v2/attacks/top/countries",
        "https://horizon.netscout.com/api/v2/global/attacks",
    ]
    rows: list[dict[str, Any]] = []
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}"} if CF_API_TOKEN else {}
    saw_quota = False
    saw_client_error = False
    for url in endpoint_candidates:
        try:
            if url.endswith("/graphql") and CF_API_TOKEN:
                query = """
                query {
                  viewer {
                    zones(filter: {zoneTag: ""}) { zonesTag }
                    attacks: radarAttacksAdaptiveGroups(limit: 50) {
                      dimensions { locationAlpha2 }
                      count
                    }
                  }
                }
                """
                resp = await client.post(url, headers={**headers, "Content-Type": "application/json"}, json={"query": query}, timeout=25)
                text = resp.text or ""
                debug_feed("ddos_telemetry", f"url={url} status={resp.status_code} bytes={len(text)}")
                if resp.status_code == 429:
                    saw_quota = True
                    continue
                if resp.status_code >= 400:
                    saw_client_error = True
                    continue
                data = resp.json()
            else:
                params = {"dateRange": "1d", "limit": "50"} if "cloudflare.com/client/v4/radar/" in url else None
                resp = await client.get(url, headers=headers, params=params, timeout=25)
                text = resp.text or ""
                debug_feed("ddos_telemetry", f"url={url} status={resp.status_code} bytes={len(text)}")
                if resp.status_code == 429:
                    saw_quota = True
                    continue
                if resp.status_code >= 400:
                    saw_client_error = True
                    continue
                data = resp.json()
        except Exception as exc:
            debug_feed("ddos_telemetry", f"url={url} error={type(exc).__name__}")
            continue
        if isinstance(data, dict):
            debug_feed("ddos_telemetry", f"url={url} top_keys={list(data.keys())[:10]}")
            if isinstance(data.get("data"), dict):
                viewer = data.get("data", {}).get("viewer", {})
                groups = viewer.get("attacks") or viewer.get("radarAttacksAdaptiveGroups") or []
                if isinstance(groups, list):
                    debug_feed("ddos_telemetry", f"url={url} graphql_groups={len(groups)}")
                    for g in groups:
                        if not isinstance(g, dict):
                            continue
                        dims = g.get("dimensions") or {}
                        rows.append(
                            {
                                "countryCode": dims.get("locationAlpha2"),
                                "count": g.get("count"),
                            }
                        )
            if isinstance(data.get("result"), dict):
                result = data.get("result", {})
                for key in ("top_0", "top", "locations", "items"):
                    arr = result.get(key)
                    if isinstance(arr, list):
                        rows.extend([r for r in arr if isinstance(r, dict)])
            result = data.get("result")
            if isinstance(result, list):
                rows.extend([r for r in result if isinstance(r, dict)])
            # Generic parser for alternative providers.
            for key in ("data", "items", "locations", "countries", "top"):
                arr = data.get(key)
                if isinstance(arr, list):
                    rows.extend([r for r in arr if isinstance(r, dict)])
                    debug_feed("ddos_telemetry", f"url={url} collected_from={key} count={len(arr)}")
        else:
            debug_feed("ddos_telemetry", f"url={url} non-dict json type={type(data).__name__}")
        if rows:
            debug_feed("ddos_telemetry", f"url={url} parsed_rows={len(rows)}")
            break
    if not rows:
        if saw_quota:
            raise RuntimeError("quota")
        # Treat client-side upstream blocks/shape changes as empty telemetry,
        # not hard feed failure, to avoid noisy red status in snapshots.
        if saw_client_error:
            return []
        return []

    out: list[dict[str, Any]] = []
    seen_cc: set[str] = set()
    for i, r in enumerate(rows):
        if len(out) >= MAX_DDOS_TELEMETRY_ROWS:
            break
        cc = country_code_from_value(
            r.get("country")
            or r.get("countryCode")
            or r.get("iso")
            or r.get("alpha2")
            or r.get("clientCountryAlpha2")
            or r.get("originCountryAlpha2")
            or (r.get("location") or {}).get("country")
        )
        if not cc or cc not in COUNTRY_CENTROIDS or cc in seen_cc:
            continue
        lat, lon = COUNTRY_CENTROIDS[cc]
        attacks = r.get("value") or r.get("count") or r.get("requests") or 0
        out.append(
            {
                "id": f"ddos-telemetry-{cc}-{i}",
                "country": cc,
                "lat": lat,
                "lon": lon,
                "type": "Cloudflare Radar DDoS telemetry",
                "attackKind": "ddos",
                "source": "cloudflare-radar-ddos",
                "ioc": f"country-telemetry:{cc}",
                "firstSeen": None,
                "locationQuality": "country-telemetry-centroid (approximate)",
                "confidence": 0.7,
                "assetCriticality": 3,
                "hoursAgo": 6,
                "kev": 0,
                "epss": 0.0,
                "telemetryCount": attacks,
            }
        )
        seen_cc.add(cc)
    return out


def chunks(items: list[str], size: int) -> list[list[str]]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def hours_since_iso8601(text: str | None, fallback: int = 6) -> int:
    if not text:
        return fallback
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - dt.astimezone(timezone.utc)
        return max(1, int(delta.total_seconds() // 3600))
    except Exception:
        return fallback


def is_ipv4(value: str | None) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.strip().split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        n = int(part)
        if n < 0 or n > 255:
            return False
    return True


def safe_url_host(value: str | None) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        p = urlparse(value)
    except Exception:
        return None
    return (p.hostname or "").strip().lower() or None


async def resolve_url_hosts_to_ipv4(urls: list[str]) -> dict[str, str]:
    hosts = [safe_url_host(u) for u in urls]
    uniq_hosts = [h for h in sorted(set([h for h in hosts if h]))][:MAX_URL_DNS_HOSTS]
    if not uniq_hosts:
        return {}
    out: dict[str, str] = {}
    loop = asyncio.get_running_loop()

    async def resolve_one(host: str) -> None:
        try:
            infos = await loop.getaddrinfo(host, None, family=2, type=1)  # AF_INET, SOCK_STREAM
        except Exception:
            return
        for item in infos:
            sockaddr = item[4] if len(item) >= 5 else None
            ip = sockaddr[0] if isinstance(sockaddr, tuple) and sockaddr else None
            if isinstance(ip, str) and is_ipv4(ip):
                out[host] = ip
                return

    await asyncio.gather(*(resolve_one(h) for h in uniq_hosts))
    return out


async def resolve_hosts_to_ipv4(hosts: list[str]) -> dict[str, str]:
    # Hostname resolver helper for domain-based IOC feeds.
    uniq_hosts = [h for h in sorted(set([str(h).strip().lower() for h in hosts if isinstance(h, str) and h.strip()]))][:MAX_URL_DNS_HOSTS]
    if not uniq_hosts:
        return {}
    out: dict[str, str] = {}
    loop = asyncio.get_running_loop()

    async def resolve_one(host: str) -> None:
        try:
            infos = await loop.getaddrinfo(host, None, family=2, type=1)  # AF_INET, SOCK_STREAM
        except Exception:
            return
        for item in infos:
            sockaddr = item[4] if len(item) >= 5 else None
            ip = sockaddr[0] if isinstance(sockaddr, tuple) and sockaddr else None
            if isinstance(ip, str) and is_ipv4(ip):
                out[host] = ip
                return

    await asyncio.gather(*(resolve_one(h) for h in uniq_hosts))
    return out


async def geolocate_ips_ip_api(client: httpx.AsyncClient, ips: list[str]) -> dict[str, dict[str, Any]]:
    # ip-api free tier uses HTTP. Keep calls batched and small.
    if not ips:
        return {}
    out: dict[str, dict[str, Any]] = {}
    url = "http://ip-api.com/batch?fields=status,message,countryCode,lat,lon,query"
    uniq = sorted(set(ips))[:MAX_IP_GEO_INPUT]
    for batch in chunks(uniq, 80):
        payload = [{"query": ip} for ip in batch]
        try:
            data = (await client.post(url, json=payload, timeout=20)).json()
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        for r in data:
            if not isinstance(r, dict):
                continue
            ip = r.get("query")
            if not ip or r.get("status") != "success":
                continue
            lat = r.get("lat")
            lon = r.get("lon")
            cc = (r.get("countryCode") or "").upper()
            if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
                out[ip] = {"lat": lat, "lon": lon, "country": cc or "UNK"}
    return out


async def fetch_feodotracker(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    # Live botnet C2 IP stream from abuse.ch Feodo Tracker.
    endpoint_candidates = [
        "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
    ]
    raw_rows: list[dict[str, Any]] = []
    for url in endpoint_candidates:
        try:
            data = (await client.get(url, timeout=20)).json()
        except Exception:
            continue
        if isinstance(data, list):
            raw_rows = [r for r in data if isinstance(r, dict)]
        elif isinstance(data, dict) and isinstance(data.get("data"), list):
            raw_rows = [r for r in data.get("data", []) if isinstance(r, dict)]
        if raw_rows:
            break

    if not raw_rows:
        return []

    sample = raw_rows[:MAX_FEODO_ROWS]
    ips = []
    for row in sample:
        ip = row.get("ip_address") or row.get("dst_ip") or row.get("ioc")
        if isinstance(ip, str) and ip.count(".") == 3:
            ips.append(ip)
    geo = await geolocate_ips_ip_api(client, ips)

    out: list[dict[str, Any]] = []
    for row in sample:
        ip = row.get("ip_address") or row.get("dst_ip") or row.get("ioc")
        if not (isinstance(ip, str) and ip in geo):
            continue
        g = geo[ip]
        first_seen = row.get("first_seen_utc") or row.get("first_seen") or row.get("date_added")
        malware = row.get("malware") or row.get("malware_family") or "Feodo C2"
        port = row.get("dst_port") or row.get("port")
        out.append(
            {
                "id": f"feodo-{ip}-{port or 'na'}",
                "country": g.get("country", "UNK"),
                "lat": g["lat"],
                "lon": g["lon"],
                "type": str(malware),
                "attackKind": "botnet-c2",
                "source": "feodotracker+ip-api",
                "ip": ip,
                "firstSeen": first_seen,
                "locationQuality": "ip-geolocated (approximate)",
                "confidence": 0.82,
                "assetCriticality": 3,
                "hoursAgo": hours_since_iso8601(first_seen, fallback=12),
                "kev": 0,
                "epss": 0.0,
            }
        )
    return out


async def fetch_spamhaus_drop(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    # Spamhaus DROP/EDROP are CIDR blocklists; geolocate using representative IPv4 from each netblock.
    urls = [
        "https://www.spamhaus.org/drop/drop.txt",
        "https://www.spamhaus.org/drop/edrop.txt",
    ]
    rows: list[str] = []
    for url in urls:
        try:
            text = (await client.get(url, timeout=20)).text
        except Exception:
            continue
        for line in text.splitlines():
            raw = line.strip()
            if not raw or raw.startswith(";"):
                continue
            cidr = raw.split(";", 1)[0].strip()
            if "/" not in cidr:
                continue
            ip = cidr.split("/", 1)[0].strip()
            if is_ipv4(ip):
                rows.append(cidr)
    if not rows:
        return []

    unique_cidrs = sorted(set(rows))[:MAX_SPAMHAUS_CIDRS]
    geo = await geolocate_ips_ip_api(client, [c.split("/", 1)[0] for c in unique_cidrs])
    out: list[dict[str, Any]] = []
    for cidr in unique_cidrs:
        ip = cidr.split("/", 1)[0]
        g = geo.get(ip)
        if not g:
            continue
        out.append(
            {
                "id": f"spamhaus-drop-{cidr}",
                "country": g.get("country", "UNK"),
                "lat": g.get("lat"),
                "lon": g.get("lon"),
                "type": "Spamhaus DROP/EDROP",
                "attackKind": "botnet-c2",
                "source": "spamhaus-drop+ip-api",
                "ip": ip,
                "ioc": cidr,
                "firstSeen": None,
                "locationQuality": "ip-geolocated (approximate)",
                "confidence": 0.8,
                "assetCriticality": 3,
                "hoursAgo": 4,
                "kev": 0,
                "epss": 0.0,
            }
        )
    return out


async def fetch_firehol_level1(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    # FireHOL level1 is a high-volume IP blocklist. Keep a bounded sample for map utility.
    url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
    try:
        text = (await client.get(url, timeout=20)).text
    except Exception:
        return []

    ips: list[str] = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        token = raw.split()[0]
        if "/" in token:
            token = token.split("/", 1)[0]
        if is_ipv4(token):
            ips.append(token)
    if not ips:
        return []

    unique_ips = sorted(set(ips))[:MAX_FIREHOL_IPS]
    geo = await geolocate_ips_ip_api(client, unique_ips)
    out: list[dict[str, Any]] = []
    for ip in unique_ips:
        g = geo.get(ip)
        if not g:
            continue
        out.append(
            {
                "id": f"firehol-l1-{ip}",
                "country": g.get("country", "UNK"),
                "lat": g.get("lat"),
                "lon": g.get("lon"),
                "type": "FireHOL Level 1",
                "attackKind": "botnet-c2",
                "source": "firehol-level1+ip-api",
                "ip": ip,
                "firstSeen": None,
                "locationQuality": "ip-geolocated (approximate)",
                "confidence": 0.74,
                "assetCriticality": 3,
                "hoursAgo": 5,
                "kev": 0,
                "epss": 0.0,
            }
        )
    return out


async def fetch_emergingthreats_compromised(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    # Emerging Threats community compromised IP list (free, no key).
    url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    try:
        text = (await client.get(url, timeout=25)).text
    except Exception:
        return []

    ips: list[str] = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        token = raw.split("#", 1)[0].strip()
        if is_ipv4(token):
            ips.append(token)
        if len(ips) >= MAX_EMERGINGTHREATS_IPS:
            break
    if not ips:
        return []

    unique_ips = sorted(set(ips))[:MAX_EMERGINGTHREATS_IPS]
    geo = await geolocate_ips_ip_api(client, unique_ips)
    out: list[dict[str, Any]] = []
    for ip in unique_ips:
        g = geo.get(ip)
        if not g:
            continue
        out.append(
            {
                "id": f"emergingthreats-{ip}",
                "country": g.get("country", "UNK"),
                "lat": g.get("lat"),
                "lon": g.get("lon"),
                "type": "Emerging Threats compromised IP",
                "attackKind": "botnet-c2",
                "source": "emergingthreats+ip-api",
                "ip": ip,
                "ioc": ip,
                "firstSeen": None,
                "locationQuality": "ip-geolocated (approximate)",
                "confidence": 0.77,
                "assetCriticality": 3,
                "hoursAgo": 4,
                "kev": 0,
                "epss": 0.0,
                "attackTactic": "Command and Control",
                "attackTechniqueId": "T1071",
                "attackTechniqueName": "Application Layer Protocol",
            }
        )
    return out


async def fetch_greensnow_blacklist(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    # GreenSnow community attack IP blacklist (free, no key).
    url = "https://blocklist.greensnow.co/greensnow.txt"
    try:
        text = (await client.get(url, timeout=25)).text
    except Exception:
        return []

    ips: list[str] = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        token = raw.split("#", 1)[0].strip()
        if is_ipv4(token):
            ips.append(token)
        if len(ips) >= MAX_GREENSNOW_IPS:
            break
    if not ips:
        return []

    unique_ips = sorted(set(ips))[:MAX_GREENSNOW_IPS]
    geo = await geolocate_ips_ip_api(client, unique_ips)
    out: list[dict[str, Any]] = []
    for ip in unique_ips:
        g = geo.get(ip)
        if not g:
            continue
        out.append(
            {
                "id": f"greensnow-{ip}",
                "country": g.get("country", "UNK"),
                "lat": g.get("lat"),
                "lon": g.get("lon"),
                "type": "GreenSnow blacklist IP",
                "attackKind": "botnet-c2",
                "source": "greensnow+ip-api",
                "ip": ip,
                "ioc": ip,
                "firstSeen": None,
                "locationQuality": "ip-geolocated (approximate)",
                "confidence": 0.76,
                "assetCriticality": 3,
                "hoursAgo": 4,
                "kev": 0,
                "epss": 0.0,
                "attackTactic": "Command and Control",
                "attackTechniqueId": "T1071",
                "attackTechniqueName": "Application Layer Protocol",
            }
        )
    return out


def build_context_events(limit: int = 40) -> list[dict[str, Any]]:
    # Fallback for sparse live feeds: blend labeled context points from local historical OSINT.
    try:
        rows = json.loads(HISTORICAL_DATA_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(rows, list):
        return []

    selected: list[dict[str, Any]] = []
    per_kind: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        lat, lon = row.get("lat"), row.get("lon")
        if not isinstance(lat, (int, float)) or not isinstance(lon, (int, float)):
            continue
        kind = str(row.get("attackKind") or row.get("type") or "unknown").lower()
        if "botnet" in kind:
            continue
        if per_kind.get(kind, 0) >= 3:
            continue
        per_kind[kind] = per_kind.get(kind, 0) + 1
        selected.append(
            {
                "id": f"context-{row.get('id', len(selected))}",
                "country": row.get("country", "UNK"),
                "lat": lat,
                "lon": lon,
                "type": row.get("type", "context-threat"),
                "attackKind": row.get("attackKind", row.get("type", "context-threat")),
                "source": "historical-context",
                "firstSeen": row.get("timestamp"),
                "locationQuality": row.get("locationQuality", "country-centroid (approximate)"),
                "confidence": float(row.get("confidence", 0.72)),
                "assetCriticality": int(row.get("assetCriticality", 3)),
                "hoursAgo": 24 * 7,
                "kev": int(row.get("kev", 0)),
                "epss": float(row.get("epss", 0.0)),
            }
        )
        if len(selected) >= limit:
            break
    return selected


async def enrich_ip_reputation(
    client: httpx.AsyncClient,
    events: list[dict[str, Any]],
    *,
    enable_abuseipdb: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    statuses = {"abuseipdb": "skipped:no-key"}
    cap = min(MAX_REPUTATION_IP_EVENTS, MAX_ABUSEIPDB_CHECKS_PER_REFRESH)
    ip_events = [e for e in events if is_ipv4(e.get("ip"))][:cap]
    if not ip_events:
        return events, {"abuseipdb": "ok:0"}
    if not enable_abuseipdb:
        return events, {"abuseipdb": "ok:0"}

    ab_ok = 0
    ab_auth_failed = False
    for e in ip_events:
        ip = e.get("ip")
        if ABUSEIPDB_API_KEY and not ab_auth_failed:
            try:
                if not reserve_abuseipdb_check():
                    statuses["abuseipdb"] = "skipped:daily-limit"
                    continue
                url = "https://api.abuseipdb.com/api/v2/check"
                params = {"ipAddress": ip, "maxAgeInDays": 90}
                headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
                r = await client.get(url, params=params, headers=headers, timeout=15)
                if r.status_code in {401, 403}:
                    ab_auth_failed = True
                    continue
                if r.status_code == 429:
                    statuses["abuseipdb"] = "quota"
                    continue
                ab = r.json().get("data", {})
                e["abuseipdb"] = {
                    "abuseConfidenceScore": ab.get("abuseConfidenceScore"),
                    "totalReports": ab.get("totalReports"),
                    "lastReportedAt": ab.get("lastReportedAt"),
                }
                ab_ok += 1
            except Exception:
                pass

    if ABUSEIPDB_API_KEY:
        if ab_auth_failed:
            statuses["abuseipdb"] = "skipped:unauthorized"
        elif statuses["abuseipdb"] != "quota":
            statuses["abuseipdb"] = f"ok:{ab_ok}"
    return events, statuses


def event_priority_score(e: dict[str, Any]) -> float:
    kev_part = 100.0 if e.get("kev") else 0.0
    epss_part = float(e.get("epss", 0.0)) * 100.0
    conf_part = float(e.get("confidence", 0.0)) * 100.0
    crit_part = (float(e.get("assetCriticality", 3)) / 5.0) * 100.0
    hours = float(e.get("hoursAgo", 24))
    recency_part = max(0.0, 100.0 - hours * 10.0)
    return 0.35 * kev_part + 0.25 * epss_part + 0.15 * conf_part + 0.15 * crit_part + 0.10 * recency_part


def capped_by_source(events: list[dict[str, Any]], per_source_cap: int, total_cap: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    cap = max(1, per_source_cap)
    for e in events:
        if len(out) >= total_cap:
            break
        src = str(e.get("source") or "unknown")
        if counts.get(src, 0) >= cap:
            continue
        out.append(e)
        counts[src] = counts.get(src, 0) + 1
    return out


def rebalance_map_kind_share(events: list[dict[str, Any]], max_botnet_ratio: float = 0.45) -> list[dict[str, Any]]:
    if not events:
        return events
    botnet = [e for e in events if infer_attack_kind(str(e.get("attackKind") or e.get("type"))) == "botnet c2"]
    other = [e for e in events if infer_attack_kind(str(e.get("attackKind") or e.get("type"))) != "botnet c2"]
    if not other:
        return events
    cap = int(len(events) * max_botnet_ratio)
    cap = max(10, cap)
    botnet = botnet[:cap]
    # Interleave for visual spread (does not change data semantics).
    out: list[dict[str, Any]] = []
    i = 0
    while i < len(other) or i < len(botnet):
        if i < len(other):
            out.append(other[i])
        if i < len(botnet):
            out.append(botnet[i])
        i += 1
    return out


async def build_live_events(
    refresh_seq: int = 1,
    include_vuln_enrichment: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    sources: dict[str, Any] = {
        "kev": "error",
        "epss": "error",
        "nvd": "error",
        "threatfox": "error",
        "feodotracker": "error",
        "spamhaus_drop": "error",
        "firehol_level1": "error",
        "emergingthreats": "error",
        "greensnow": "error",
        "openphish": "error",
        "phishtank": "error",
        "urlhaus": "error",
        "malwarebazaar": "error",
        "depsdev": "error",
        "osv": "error",
        "pulsedive": "error",
        "otx": "skipped:no-key",
        "circl": "error",
        "ransomware_live": "error",
        "ddos_telemetry": "error",
        "cisa_alerts": "error",
        "urlscan": "error",
        "shodan": "skipped:no-key",
        "censys": "skipped:no-key",
        "abuseipdb": "skipped:no-key",
        "context": "off",
    }
    async with httpx.AsyncClient(follow_redirects=True, headers={"User-Agent": "cyber-dashboard/1.0"}) as client:
        kev = []
        epss_map: dict[str, float] = {}
        nvd_map: dict[str, dict[str, Any]] = {}
        if include_vuln_enrichment:
            try:
                kev = await fetch_kev(client)
                sources["kev"] = f"ok:{len(kev)}"
            except Exception:
                kev = []

            try:
                epss_map = await fetch_epss(client, [k["cve"] for k in kev if k.get("cve")])
                sources["epss"] = f"ok:{len(epss_map)}"
            except Exception:
                epss_map = {}

            try:
                nvd_map = await fetch_nvd_enrichment(client, [k["cve"] for k in kev if k.get("cve")])
                sources["nvd"] = f"ok:{len(nvd_map)}"
            except Exception:
                nvd_map = {}
        else:
            sources["kev"] = "skipped:degraded"
            sources["epss"] = "skipped:degraded"
            sources["nvd"] = "skipped:degraded"

        def cadence_allows(every: int) -> bool:
            if every <= 1:
                return True
            return ((refresh_seq - 1) % every) == 0

        async def run_feed(name: str, fn: Any, *, no_key: bool = False, cadence_every: int = 1) -> list[dict[str, Any]]:
            if no_key:
                sources[name] = "skipped:no-key"
                return []
            if not cadence_allows(cadence_every):
                # Planned skip to preserve daily quota/limits.
                sources[name] = "ok:0"
                return []
            if name == "urlscan" and not reserve_urlscan_request():
                sources[name] = "skipped:daily-limit"
                return []
            if name == "shodan" and not reserve_shodan_request():
                sources[name] = "skipped:daily-limit"
                return []
            if name == "censys" and not reserve_censys_request():
                sources[name] = "skipped:daily-limit"
                return []
            try:
                rows = await fn(client)
                sources[name] = f"ok:{len(rows)}"
                return rows
            except Exception as exc:
                msg = str(exc).lower()
                if "cooldown" in msg:
                    sources[name] = "skipped:cooldown"
                elif "daily_limit" in msg:
                    sources[name] = "skipped:daily-limit"
                elif "quota" in msg or "429" in msg:
                    sources[name] = "quota"
                elif "client_error" in msg:
                    sources[name] = "error:client_error"
                elif "forbidden" in msg or "403" in msg:
                    sources[name] = "skipped:forbidden"
                else:
                    sources[name] = f"error:{type(exc).__name__}"
                return []

        feed_tasks = await asyncio.gather(
            run_feed("threatfox", fetch_threatfox),
            run_feed("feodotracker", fetch_feodotracker),
            run_feed("spamhaus_drop", fetch_spamhaus_drop),
            run_feed("firehol_level1", fetch_firehol_level1),
            run_feed("emergingthreats", fetch_emergingthreats_compromised),
            run_feed("greensnow", fetch_greensnow_blacklist),
            run_feed("openphish", fetch_openphish),
            run_feed("phishtank", fetch_phishtank),
            run_feed("urlhaus", fetch_urlhaus),
            run_feed("malwarebazaar", fetch_malwarebazaar),
            run_feed("depsdev", fetch_depsdev_supply_chain, cadence_every=DEPSDEV_REFRESH_EVERY),
            run_feed("osv", fetch_osv_supply_chain, cadence_every=OSV_REFRESH_EVERY),
            run_feed("pulsedive", fetch_pulsedive, cadence_every=PULSEDIVE_REFRESH_EVERY),
            run_feed("otx", fetch_otx, no_key=not bool(OTX_API_KEY)),
            run_feed("circl", fetch_circl_recent),
            run_feed("ransomware_live", fetch_ransomware_live),
            run_feed("ddos_telemetry", fetch_ddos_country_telemetry),
            run_feed("cisa_alerts", fetch_cisa_alerts, cadence_every=CISA_REFRESH_EVERY),
            run_feed("urlscan", fetch_urlscan_recent, cadence_every=URLSCAN_REFRESH_EVERY),
            run_feed("shodan", fetch_shodan_activity, no_key=not bool(SHODAN_API_KEY), cadence_every=SHODAN_REFRESH_EVERY),
            run_feed("censys", fetch_censys_activity, no_key=not (bool(CENSYS_API_ID) and bool(CENSYS_API_SECRET)), cadence_every=CENSYS_REFRESH_EVERY),
        )
        (
            tf,
            feodo,
            spamhaus_drop,
            firehol_level1,
            emergingthreats,
            greensnow,
            openphish,
            phishtank,
            urlhaus,
            malwarebazaar,
            depsdev,
            osv,
            pulsedive,
            otx,
            circl,
            ransomware_live,
            ddos_telemetry,
            cisa_alerts,
            urlscan,
            shodan,
            censys,
        ) = feed_tasks

        pulsedive_geo = [e for e in pulsedive if isinstance(e.get("lat"), (int, float)) and isinstance(e.get("lon"), (int, float))]
        pulsedive_alert_only = [e for e in pulsedive if not (isinstance(e.get("lat"), (int, float)) and isinstance(e.get("lon"), (int, float)))]
        live_geo = tf + feodo + spamhaus_drop + firehol_level1 + emergingthreats + greensnow + urlhaus + otx + pulsedive_geo + ransomware_live + ddos_telemetry + urlscan + shodan + censys
        # IP reputation enrichment should run while client is active.
        live_geo, rep_status = await enrich_ip_reputation(
            client,
            live_geo,
            enable_abuseipdb=cadence_allows(ABUSEIPDB_REFRESH_EVERY),
        )
        sources["abuseipdb"] = rep_status.get("abuseipdb", sources["abuseipdb"])

    # KEV events are high-priority alert intelligence but not geolocated incident points.
    kev_events: list[dict[str, Any]] = []
    for k in kev[:MAX_KEV_EVENTS]:
        epss = epss_map.get(k.get("cve"), 0.0)
        nvd = nvd_map.get(k.get("cve"), {})
        kev_events.append(
            {
                "id": f"kev-{k.get('cve')}",
                "country": "GLOBAL",
                "lat": None,
                "lon": None,
                "type": f"KEV {k.get('cve')}",
                "attackKind": "known-exploited-vulnerability",
                "source": "kev+epss",
                "firstSeen": k.get("dateAdded"),
                "locationQuality": "not-geolocated",
                "kev": 1,
                "epss": epss,
                "nvd": nvd,
                "confidence": 0.9,
                "assetCriticality": 4,
                "hoursAgo": 8,
            }
        )

    # Non-geolocated but live alert events.
    live_alert_only = openphish + phishtank + malwarebazaar + depsdev + osv + pulsedive_alert_only + circl + cisa_alerts + urlscan
    unique_kinds = {str(e.get("attackKind", "")).lower() for e in live_geo}
    if len(live_geo) < 20 or len(unique_kinds) < 2:
        context = build_context_events(limit=MAX_CONTEXT_EVENTS)
        if context:
            live_geo = live_geo + context
            sources["context"] = f"on:{len(context)}"
    # Diversity-aware composition: reserve space for alert-only and KEV streams.
    kev_quota = max(40, min(120, MAX_TOTAL_EVENTS // 5))
    alert_quota = max(120, min(220, MAX_TOTAL_EVENTS // 3))
    geo_quota = max(120, MAX_TOTAL_EVENTS - kev_quota - alert_quota)

    geo_ranked = sorted(live_geo, key=event_priority_score, reverse=True)
    geo_selected = capped_by_source(geo_ranked, per_source_cap=max(35, geo_quota // 4), total_cap=geo_quota)
    alert_ranked = sorted(live_alert_only, key=event_priority_score, reverse=True)
    alert_selected = capped_by_source(alert_ranked, per_source_cap=max(25, alert_quota // 5), total_cap=alert_quota)
    kev_selected = kev_events[:kev_quota]
    events = (geo_selected + alert_selected + kev_selected)[:MAX_TOTAL_EVENTS]
    events = apply_attack_taxonomy(events)
    return events, sources


async def get_cached_events(force: bool = False) -> tuple[list[dict[str, Any]], dict[str, Any], bool]:
    now = time.time()
    stale = (now - state["last_fetch"]) > CACHE_TTL_SECONDS
    if force or stale or not state["events"]:
        try:
            state["refresh_seq"] = int(state.get("refresh_seq", 0)) + 1
            # Feed graph includes multiple sequential enrichment calls; allow a wider refresh window
            # so we don't drop to context-only mode under normal upstream latency.
            events, sources = await asyncio.wait_for(build_live_events(refresh_seq=int(state["refresh_seq"])), timeout=95)
        except Exception:
            # Degraded retry: skip slower vuln-enrichment stage and keep core feeds live.
            try:
                events, sources = await asyncio.wait_for(
                    build_live_events(
                        refresh_seq=int(state.get("refresh_seq", 1)),
                        include_vuln_enrichment=False,
                    ),
                    timeout=45,
                )
            except Exception:
                events, sources = [], {}
        if events:
            state["events"] = events
            state["sources"] = sources
            state["source_health"] = compute_source_health(sources)
            state["last_fetch"] = now
            return events, sources, True
        if state["events"]:
            # Keep stale cache if refresh is slow/unavailable.
            return state["events"], state["sources"], False
        # Fail-open so API stays responsive even if upstream feeds are slow.
        if not state["events"]:
            fallback = build_context_events(limit=min(40, MAX_TOTAL_EVENTS))
            state["events"] = fallback
            last_sources = state.get("sources") or {}
            state["sources"] = {**last_sources, "context": f"on:{len(fallback)}"}
            state["source_health"] = compute_source_health(state["sources"])
            state["last_fetch"] = now
            return state["events"], state["sources"], True
    return state["events"], state["sources"], False


def compute_source_health(sources: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for name, raw in (sources or {}).items():
        status = str(raw)
        reason = "ok"
        count = None
        if status.startswith("ok:"):
            try:
                count = int(status.split(":", 1)[1])
            except Exception:
                count = None
            if count == 0:
                reason = "upstream_empty"
        elif status.startswith("skipped:no-key"):
            reason = "no_key"
        elif status.startswith("skipped:cooldown"):
            reason = "throttled"
        elif status.startswith("skipped:daily-limit"):
            reason = "throttled"
        elif status.startswith("skipped:forbidden"):
            reason = "upstream_empty"
        elif status.startswith("skipped:degraded"):
            reason = "upstream_empty"
        elif "forbidden" in status.lower() or "403" in status.lower():
            reason = "error"
        elif status.startswith("on:"):
            reason = "fallback_on"
            try:
                count = int(status.split(":", 1)[1])
            except Exception:
                count = None
        elif status == "off":
            reason = "fallback_off"
        elif "quota" in status.lower() or "rate" in status.lower() or "429" in status.lower():
            reason = "quota"
        else:
            reason = "error"
        out[name] = {"status": status, "reason": reason, "count": count}
    return out


def build_balanced_live_map_events(
    live_events: list[dict[str, Any]],
    context_events: list[dict[str, Any]],
    max_events: int,
) -> tuple[list[dict[str, Any]], bool]:
    # Keep map representative: prevent one category (usually botnet-c2) from dominating.
    if not live_events:
        return context_events[: min(max_events, len(context_events))], bool(context_events)

    groups: dict[str, list[dict[str, Any]]] = {}
    for e in live_events:
        kind = infer_attack_kind(str(e.get("attackKind") or e.get("type")))
        groups.setdefault(kind, []).append(e)

    total_live = len(live_events)
    botnet_count = len(groups.get("botnet c2", []))
    botnet_ratio = (botnet_count / total_live) if total_live else 0.0
    live_unique = len(groups)

    # If live feed is diverse enough, keep strict live map behavior.
    if live_unique >= 4 and botnet_ratio <= 0.6:
        return live_events[:max_events], False

    out: list[dict[str, Any]] = []
    used_ids: set[str] = set()
    source_counts: dict[str, int] = {}
    per_source_cap = max(8, max_events // 7)
    per_kind_cap = max(8, max_events // 9)
    botnet_cap = max(14, max_events // 5)
    target_non_botnet_kinds = 5

    def add_event(e: dict[str, Any], force: bool = False) -> bool:
        eid = str(e.get("id") or "")
        if eid and eid in used_ids:
            return False
        src = str(e.get("source") or "unknown")
        if not force and source_counts.get(src, 0) >= per_source_cap:
            return False
        out.append(e)
        if eid:
            used_ids.add(eid)
        source_counts[src] = source_counts.get(src, 0) + 1
        return True

    # Pass 1: one item per non-botnet category (maximizes glossary coverage).
    for kind, events in groups.items():
        if kind == "botnet c2":
            continue
        if events:
            add_event(events[0], force=True)
        if len(out) >= max_events:
            return out[:max_events], False

    # Pass 2: round-robin non-botnet additions with per-source caps.
    non_botnet_kinds = [k for k in groups.keys() if k != "botnet c2"]
    for i in range(per_kind_cap):
        if len(out) >= max_events:
            break
        progressed = False
        for kind in non_botnet_kinds:
            rows = groups.get(kind, [])
            if i >= len(rows):
                continue
            if add_event(rows[i]):
                progressed = True
            if len(out) >= max_events:
                break
        if not progressed:
            break

    # Pass 3: bounded botnet slice, still source-capped.
    botnet_rows = groups.get("botnet c2", [])[: max(botnet_cap * 3, botnet_cap)]
    for e in botnet_rows:
        if len(out) >= max_events:
            break
        if sum(1 for x in out if infer_attack_kind(str(x.get("attackKind") or x.get("type"))) == "botnet c2") >= botnet_cap:
            break
        add_event(e)

    out_kinds = {infer_attack_kind(str(e.get("attackKind") or e.get("type"))) for e in out}
    need_context = len(out_kinds) < target_non_botnet_kinds and bool(context_events)
    if not need_context:
        return out, False

    # Blend context events by unseen categories to improve glossary coverage.
    context_groups: dict[str, list[dict[str, Any]]] = {}
    for e in context_events:
        kind = infer_attack_kind(str(e.get("attackKind") or e.get("type")))
        if kind == "botnet c2":
            continue
        context_groups.setdefault(kind, []).append(e)

    for kind, events in context_groups.items():
        if len(out) >= max_events:
            break
        if kind in out_kinds:
            continue
        out.append(events[0])
        out_kinds.add(kind)
        if len(out_kinds) >= target_non_botnet_kinds:
            break

    # Fill remaining slots from context (non-botnet only), bounded.
    if len(out) < max_events:
        for kind, events in context_groups.items():
            if len(out) >= max_events:
                break
            for e in events[:2]:
                if len(out) >= max_events:
                    break
                out.append(e)

    return out[:max_events], True


def build_projected_alert_map_events(
    events: list[dict[str, Any]],
    existing_map_events: list[dict[str, Any]],
    max_add: int = 60,
) -> list[dict[str, Any]]:
    # Project non-geolocated live alerts to regional hubs so glossary categories
    # are represented on the live map when geolocation is unavailable.
    if max_add <= 0:
        return []
    existing_kinds = {infer_attack_kind(str(e.get("attackKind") or e.get("type"))) for e in existing_map_events}
    candidates = [
        e for e in events
        if not (isinstance(e.get("lat"), (int, float)) and isinstance(e.get("lon"), (int, float)))
        and e.get("source") != "historical-context"
    ]
    if not candidates:
        return []

    hubs = [
        ("US", COUNTRY_CENTROIDS["US"]),
        ("GB", COUNTRY_CENTROIDS["GB"]),
        ("DE", COUNTRY_CENTROIDS["DE"]),
        ("IN", COUNTRY_CENTROIDS["IN"]),
        ("SG", COUNTRY_CENTROIDS["SG"]),
        ("BR", COUNTRY_CENTROIDS["BR"]),
        ("AU", COUNTRY_CENTROIDS["AU"]),
    ]

    # Prioritize categories not yet present on map, with focus on non-botnet glossary diversity.
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for e in candidates:
        kind = infer_attack_kind(str(e.get("attackKind") or e.get("type")))
        by_kind.setdefault(kind, []).append(e)

    priority_kinds = [
        "phishing / social engineering",
        "ransomware",
        "ddos",
        "web/api exploitation",
        "credential theft",
        "supply chain compromise",
        "cloud account / iam abuse",
        "zero-day exploitation",
        "business email compromise",
        "insider threat",
    ]

    projected: list[dict[str, Any]] = []
    hub_idx = 0
    ordered_kinds = priority_kinds + [k for k in by_kind.keys() if k not in priority_kinds]
    for kind in ordered_kinds:
        rows = by_kind.get(kind, [])
        if not rows:
            continue
        if len(projected) >= max_add:
            break
        if kind in existing_kinds:
            continue
        base = rows[0]
        cc, (lat, lon) = hubs[hub_idx % len(hubs)]
        hub_idx += 1
        projected.append(
            {
                **base,
                "id": f"projected-{base.get('id', len(projected))}",
                "country": cc,
                "lat": lat,
                "lon": lon,
                "source": f"{base.get('source', 'live-alert')}-projected",
                "locationQuality": "projected-from-live-alert (not-incident-location)",
                "confidence": float(base.get("confidence", 0.65)) * 0.9,
            }
        )
        existing_kinds.add(kind)

    # Fill remaining slots with a small rotating sample.
    if len(projected) < max_add:
        for i, base in enumerate(candidates):
            if len(projected) >= max_add:
                break
            kind = infer_attack_kind(str(base.get("attackKind") or base.get("type")))
            cc, (lat, lon) = hubs[(hub_idx + i) % len(hubs)]
            projected.append(
                {
                    **base,
                    "id": f"projected-extra-{base.get('id', i)}",
                    "country": cc,
                    "lat": lat,
                    "lon": lon,
                    "source": f"{base.get('source', 'live-alert')}-projected",
                    "locationQuality": "projected-from-live-alert (not-incident-location)",
                    "confidence": float(base.get("confidence", 0.65)) * 0.85,
                }
            )
    return projected[:max_add]


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"ok": True, "cached_events": len(state["events"]), "last_fetch": state["last_fetch"]}


@app.get("/api/live-threats")
async def live_threats(force_refresh: bool = False) -> dict[str, Any]:
    events, sources, refreshed = await get_cached_events(force_refresh)
    source_health = state.get("source_health") or compute_source_health(sources)
    map_events_all_geo = [e for e in events if isinstance(e.get("lat"), (int, float)) and isinstance(e.get("lon"), (int, float))]
    live_only_map_events = [e for e in map_events_all_geo if e.get("source") != "historical-context"]
    context_map_events = [e for e in map_events_all_geo if e.get("source") == "historical-context"]
    # Prefer live-only map; blend historical context only when live geolocated coverage is sparse.
    map_events, include_context_on_map = build_balanced_live_map_events(
        live_events=live_only_map_events,
        context_events=context_map_events,
        max_events=MAX_TOTAL_EVENTS,
    )
    # Add projected live alerts when non-botnet categories are underrepresented.
    map_unique_kinds = {infer_attack_kind(str(e.get("attackKind") or e.get("type"))) for e in map_events}
    map_non_botnet_count = sum(1 for e in map_events if infer_attack_kind(str(e.get("attackKind") or e.get("type"))) != "botnet c2")
    needs_projection = (len(map_unique_kinds) < 9) or (map_non_botnet_count < 40)
    projected_added = 0
    if needs_projection:
        projected = build_projected_alert_map_events(events=events, existing_map_events=map_events, max_add=90)
        if projected:
            room = max(0, MAX_TOTAL_EVENTS - len(map_events))
            to_add = projected[:room]
            map_events = map_events + to_add
            projected_added = len(to_add)
    map_events = rebalance_map_kind_share(map_events, max_botnet_ratio=0.25)
    alert_events = events
    return {
        "generated_at": int(time.time()),
        "refreshed": refreshed,
        "count": len(events),
        "map_count": len(map_events),
        "map_count_context": len(context_map_events),
        "map_context_included": include_context_on_map,
        "map_projected_alerts": projected_added,
        "sources": sources,
        "source_health": source_health,
        "events": alert_events,
        "map_events": map_events,
        "map_semantics": {
            "what_hotspot_means": "A geolocated malicious IOC/telemetry point from live feeds (ThreatFox, Feodo, Spamhaus DROP/EDROP, FireHOL Level 1, URLhaus, OTX, Pulsedive, ransomware.live, Cloudflare Radar).",
            "location_note": "Coordinates are approximate: country-centroid or IP-geolocation.",
            "not_shown_on_map": "KEV/CVE records are excluded. Historical-context is blended only when live geolocated categories are too narrow.",
            "projected_alerts_note": "Some non-geolocated live alerts may be projected to regional hubs to improve category visibility; these are not exact incident locations."
        },
    }


@app.get("/api/source-health")
async def source_health(force_refresh: bool = False) -> dict[str, Any]:
    events, sources, refreshed = await get_cached_events(force_refresh)
    health_map = state.get("source_health") or compute_source_health(sources)
    return {
        "generated_at": int(time.time()),
        "refreshed": refreshed,
        "cached_events": len(events),
        "sources": health_map,
        "legend": {
            "ok": "Source is reachable and returned data.",
            "upstream_empty": "Source reachable but returned 0 items for current query/time window.",
            "no_key": "API key missing in backend environment.",
            "throttled": "Source intentionally paced/skipped to preserve daily budget.",
            "quota": "Source likely hit rate/quota limit.",
            "error": "Source request failed or parse failed.",
            "fallback_on": "Local context fallback enabled to maintain map utility.",
            "fallback_off": "Local context fallback not active."
        }
    }


@app.on_event("startup")
async def startup_prefetch() -> None:
    # Warm cache in background; do not block API availability.
    async def _warm() -> None:
        try:
            await asyncio.wait_for(get_cached_events(force=True), timeout=30)
        except Exception:
            return
    asyncio.create_task(_warm())
