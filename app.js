const utcNow = document.getElementById("utcNow");
const lastSyncBadge = document.getElementById("lastSyncBadge");
let lastSyncedAt = null;

function formatUtcNow() {
  return new Date().toISOString().replace("T", " ").slice(0, 19);
}

function formatAgo(ts) {
  if (!ts) return "--";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "--";
  const s = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return `${h}h ago`;
}

function updateTopBadges() {
  if (utcNow) utcNow.textContent = formatUtcNow();
  if (lastSyncBadge) lastSyncBadge.textContent = `Last sync: ${formatAgo(lastSyncedAt)}`;
}

updateTopBadges();

const MAPTILER_KEY = localStorage.getItem("MAPTILER_KEY") || "";
const SNAPSHOT_ENDPOINTS = ["./data/live-threats.json"];

const sourceCatalog = [
  { name: "CISA KEV Catalog (JSON)", type: "Known exploited vulnerabilities", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
  { name: "NVD API 2.0", type: "CVE metadata & CVSS", url: "https://nvd.nist.gov/developers/api-workflows" },
  { name: "FIRST EPSS API", type: "Exploit probability scoring", url: "https://api.first.org/data/v1/epss" },
  { name: "abuse.ch ThreatFox API", type: "Malware IOC stream", url: "https://threatfox.abuse.ch/api/" },
  { name: "Spamhaus DROP/EDROP", type: "High-risk netblock feed", url: "https://www.spamhaus.org/blocklists/do-not-route-or-peer/" },
  { name: "FireHOL Level 1", type: "Aggregated abusive IP feed", url: "https://github.com/firehol/blocklist-ipsets" },
  { name: "OpenPhish Feed", type: "Live phishing URL stream", url: "https://openphish.com/phishing_feeds.html" },
  { name: "PhishTank Feed", type: "Community phishing URL feed", url: "https://phishtank.org/" },
  { name: "abuse.ch URLhaus API", type: "Malware URL/host IOC stream", url: "https://urlhaus-api.abuse.ch/" },
  { name: "abuse.ch MalwareBazaar API", type: "Malware sample intel stream", url: "https://bazaar.abuse.ch/api/" },
  { name: "deps.dev API v3", type: "Dependency/advisory supply-chain context", url: "https://docs.deps.dev/api/v3/" },
  { name: "OSV API", type: "Open-source vulnerability advisory feed", url: "https://osv.dev/docs/" },
  { name: "AlienVault OTX API", type: "Threat pulse IOC stream", url: "https://otx.alienvault.com/api" },
  { name: "Pulsedive API", type: "IOC stream with tags/types", url: "https://pulsedive.com/api/" },
  { name: "CIRCL CVE API", type: "Recent vulnerability advisory feed", url: "https://cve.circl.lu/" },
  { name: "urlscan.io API", type: "Suspicious/malicious web scan telemetry", url: "https://urlscan.io/docs/api/" },
  { name: "Shodan API", type: "Internet-exposed host/service telemetry", url: "https://developer.shodan.io/api" },
  { name: "Censys Search API", type: "Exposed host telemetry and internet surface data", url: "https://docs.censys.com/docs/platform-search-api" },
  { name: "CISA Advisories XML", type: "Live advisory intelligence feed", url: "https://www.cisa.gov/cybersecurity-advisories" },
  { name: "ransomware.live API", type: "Ransomware victim post telemetry by country", url: "https://ransomware.live/" },
  { name: "Cloudflare Radar", type: "Country-level DDoS telemetry", url: "https://radar.cloudflare.com/" },
  { name: "AbuseIPDB API", type: "Abusive IP reputation", url: "https://www.abuseipdb.com/api" }
];

const attackGlossary = [
  { key: "all", type: "All Threats", meaning: "Show all currently observed threat categories." },
  {
    key: "ransomware",
    type: "Ransomware",
    meaning:
      "Malware encrypts files/systems and demands payment. Often paired with data theft and extortion."
  },
  {
    key: "credential_theft",
    type: "Credential Theft",
    meaning:
      "Adversary steals usernames, passwords, tokens, or session cookies to impersonate users."
  },
  {
    key: "supply_chain",
    type: "Supply Chain Compromise",
    meaning:
      "Attacker compromises software dependencies, build pipelines, or trusted vendors to reach downstream targets."
  },
  {
    key: "ddos",
    type: "DDoS",
    meaning:
      "Distributed traffic flood designed to degrade or take services offline."
  },
  {
    key: "botnet_c2",
    type: "Botnet C2",
    meaning:
      "Command-and-control infrastructure used to coordinate infected devices for malicious actions."
  },
  {
    key: "kev",
    type: "Known Exploited Vulnerability (KEV)",
    meaning:
      "A vulnerability confirmed as actively exploited in the wild; usually patch and mitigation priority."
  },
  {
    key: "zero_day",
    type: "Zero-Day Exploitation",
    meaning:
      "Attack against a vulnerability before broad defensive updates are available."
  },
  {
    key: "phishing",
    type: "Phishing / Social Engineering",
    meaning:
      "Manipulating people into disclosing credentials, running malware, or granting access."
  },
  {
    key: "bec",
    type: "Business Email Compromise (BEC)",
    meaning:
      "Impersonation fraud targeting payments, invoices, or sensitive business workflows."
  },
  {
    key: "wiper",
    type: "Wiper / Destructive Malware",
    meaning:
      "Malware designed to destroy data or disrupt operations rather than monetize directly."
  },
  {
    key: "cloud_iam",
    type: "Cloud Account / IAM Abuse",
    meaning:
      "Unauthorized use of cloud identities, permissions, and tokens to access resources."
  },
  {
    key: "web_exploit",
    type: "Web/API Exploitation",
    meaning:
      "Exploitation of web apps or APIs (e.g., RCE/auth bypass/injection) for initial access."
  },
  {
    key: "insider",
    type: "Insider Threat",
    meaning:
      "Malicious or negligent internal actor causing data loss, fraud, or unauthorized access."
  },
  {
    key: "unknown",
    type: "Other / Unclassified",
    meaning:
      "Threat activity observed but not confidently mapped to a known category."
  }
];

let allMapEvents = [];
let activeThreatKey = "all";
let expandedThreatKey = null;
let liveMapEvents = [];
let liveAlertEvents = [];
let historicalEvents = [];
let liveSourceHealth = {};
const BALANCED_MAP_MODE = true;
const THREAT_LOG_STORAGE_KEY = "threat_log_v1";
const THREAT_LOG_MAX = 300;
const LIVE_CACHE_STORAGE_KEY = "live_cache_v1";
let threatLog = [];
let liveLoadingTimeoutId = null;

const THREAT_COLORS = {
  ransomware: "#ff4d6d",
  credential_theft: "#ff9f1c",
  supply_chain: "#6366f1",
  ddos: "#0ea5e9",
  botnet_c2: "#14b8a6",
  kev: "#ffd166",
  zero_day: "#ec4899",
  phishing: "#84cc16",
  bec: "#f97316",
  wiper: "#b91c1c",
  cloud_iam: "#38bdf8",
  web_exploit: "#a855f7",
  insider: "#64748b",
  unknown: "#94a3b8",
  all: "#9bdcff"
};

const THREAT_ICONS = {
  ransomware: "./assets/icons/ransomware.svg",
  credential_theft: "./assets/icons/credential_theft.svg",
  supply_chain: "./assets/icons/supply_chain.svg",
  ddos: "./assets/icons/ddos.svg",
  botnet_c2: "./assets/icons/botnet_c2.svg",
  kev: "./assets/icons/kev.svg",
  zero_day: "./assets/icons/zero_day.svg",
  phishing: "./assets/icons/phishing.svg",
  bec: "./assets/icons/bec.svg",
  wiper: "./assets/icons/wiper.svg",
  cloud_iam: "./assets/icons/cloud_iam.svg",
  web_exploit: "./assets/icons/web_exploit.svg",
  insider: "./assets/icons/insider.svg",
  unknown: "./assets/icons/unknown.svg"
};

const THREAT_SOURCE_MAP = {
  ransomware: ["ransomware.live", "ThreatFox", "Pulsedive", "CISA Advisories"],
  credential_theft: ["OpenPhish", "PhishTank", "Pulsedive", "CISA Advisories"],
  supply_chain: ["CISA Advisories", "CIRCL", "Pulsedive"],
  ddos: ["Cloudflare Radar", "Pulsedive", "CISA Advisories"],
  botnet_c2: ["Spamhaus DROP/EDROP", "Feodo Tracker", "FireHOL", "ThreatFox"],
  kev: ["CISA KEV", "FIRST EPSS", "NVD"],
  zero_day: ["CIRCL", "CISA Advisories", "Pulsedive"],
  phishing: ["OpenPhish", "PhishTank", "URLhaus", "Pulsedive"],
  bec: ["CISA Advisories", "OpenPhish", "PhishTank"],
  wiper: ["ThreatFox", "CIRCL", "CISA Advisories"],
  cloud_iam: ["CISA Advisories", "Pulsedive", "OTX"],
  web_exploit: ["URLhaus", "Pulsedive", "CIRCL", "CISA Advisories"],
  insider: ["CISA Advisories", "CIRCL"],
  unknown: ["ThreatFox", "Pulsedive", "CIRCL"]
};

function normalizeThreatKey(text, source = "") {
  const t = String(text || "").toLowerCase();
  const s = String(source || "").toLowerCase();
  if (t.includes("ransom")) return "ransomware";
  if (t.includes("credential") || t.includes("stealer") || t.includes("token")) return "credential_theft";
  if (t.includes("supply") || t.includes("dependency") || t.includes("typosquat")) return "supply_chain";
  if (t.includes("ddos") || t.includes("dos")) return "ddos";
  if (t.includes("botnet") || t.includes("c2") || t.includes("command")) return "botnet_c2";
  if (t.includes("kev") || t.includes("cve")) return "kev";
  if (t.includes("zero-day") || t.includes("zero day")) return "zero_day";
  if (t.includes("phish") || t.includes("social engineering")) return "phishing";
  if (t.includes("bec") || t.includes("invoice")) return "bec";
  if (t.includes("wiper") || t.includes("destructive")) return "wiper";
  if (t.includes("iam") || t.includes("cloud")) return "cloud_iam";
  if (t.includes("web") || t.includes("api") || t.includes("injection") || t.includes("rce")) return "web_exploit";
  if (t.includes("insider")) return "insider";
  if (t.includes("ioc") || t.includes("malicious ip") || t.includes("c2 infra")) return "botnet_c2";
  if (t.includes("malware") || t.includes("trojan") || t.includes("loader") || t.includes("backdoor")) return "botnet_c2";
  if (s.includes("openphish") || s.includes("phishtank")) return "phishing";
  if (s.includes("urlhaus")) return "web_exploit";
  if (s.includes("malwarebazaar") || s.includes("threatfox") || s.includes("feodo") || s.includes("spamhaus") || s.includes("firehol") || s.includes("otx")) return "botnet_c2";
  if (s.includes("pulsedive")) return "web_exploit";
  if (s.includes("cisa") || s.includes("circl")) return "web_exploit";
  if (s.includes("depsdev") || s.includes("osv")) return "supply_chain";
  if (s.includes("ransomware.live")) return "ransomware";
  return "unknown";
}


const scoreAlert = (e) => {
  const kevPart = e.kev ? 100 : 0;
  const epssPart = e.epss * 100;
  const confidencePart = e.confidence * 100;
  const critPart = (e.assetCriticality / 5) * 100;
  const recencyPart = Math.max(0, 100 - e.hoursAgo * 10);
  return (
    0.35 * kevPart +
    0.25 * epssPart +
    0.15 * confidencePart +
    0.15 * critPart +
    0.10 * recencyPart
  );
};

const severityBand = (score) => (score >= 75 ? "high" : score >= 50 ? "medium" : "low");

function uniqueStrings(values = []) {
  return [...new Set(values.filter((v) => typeof v === "string" && v.trim().length))];
}

function drawMap(events) {
  const el = document.getElementById("worldMap");
  if (el._leaflet_id) {
    el._leaflet_map.remove();
  }

  const map = L.map(el, { zoomControl: true }).setView([20, 0], 2);
  el._leaflet_map = map;

  if (MAPTILER_KEY) {
    L.tileLayer(`https://api.maptiler.com/maps/backdrop/{z}/{x}/{y}.png?key=${MAPTILER_KEY}`, {
      maxZoom: 7,
      attribution: '&copy; MapTiler &copy; OpenStreetMap contributors'
    }).addTo(map);
  } else {
    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
      maxZoom: 7,
      subdomains: "abcd",
      attribution: '&copy; OpenStreetMap contributors &copy; CARTO'
    }).addTo(map);
  }

  const coordUse = new Map();
  events.forEach((e) => {
    const score = scoreAlert(e);
    const isLegacy = (e.timestamp || "").slice(0, 4) < "2021";
    const threatKey = normalizeThreatKey(e.attackKind || e.type, e.source);
    const color = THREAT_COLORS[threatKey] || THREAT_COLORS.unknown;
    const iconPath = THREAT_ICONS[threatKey] || THREAT_ICONS.unknown;
    const size = Math.round(20 + (score / 100) * 14);
    const icon = L.divIcon({
      className: "threat-marker",
      iconSize: [size, size],
      iconAnchor: [Math.round(size / 2), Math.round(size / 2)],
      popupAnchor: [0, -Math.round(size / 2)],
      html: `
        <div class="threat-pin ${isLegacy ? "legacy" : ""}" style="--threat-color:${color};width:${size}px;height:${size}px;">
          <img src="${iconPath}" alt="${threatKey}" />
        </div>
      `
    });
    const key = `${Number(e.lat).toFixed(4)},${Number(e.lon).toFixed(4)}`;
    const seen = coordUse.get(key) || 0;
    coordUse.set(key, seen + 1);
    // Prevent stacked markers at identical coordinates from hiding events.
    const angle = seen * 0.8;
    const radius = Math.min(1.4, 0.12 * seen);
    const plotLat = Number(e.lat) + Math.sin(angle) * radius;
    const plotLon = Number(e.lon) + Math.cos(angle) * radius;
    const marker = L.marker([plotLat, plotLon], { icon }).addTo(map);

    const seenRaw = e.firstSeen || e.timestamp || null;
    const seenIso = seenRaw ? new Date(seenRaw).toISOString() : null;
    const seenText = seenIso ? `${seenIso.replace("T", " ").slice(0, 19)} UTC` : "unknown";
    const attackKind = e.attackKind || e.type;
    const source = e.source || "unknown";
    const locationQuality = e.locationQuality || "unknown";
    const confidencePct = Math.round((Number(e.confidence || 0) * 100));
    const ipText = e.ip || "n/a";
    const abuseScore = e.abuseipdb?.abuseConfidenceScore;
    const abuseReports = e.abuseipdb?.totalReports;
    const nvdCvss = e.nvd?.cvss;
    const nvdCwe = e.nvd?.cwe;
    const mitreTactic = e.attackTactic || "n/a";
    const mitreTechniqueId = e.attackTechniqueId || "n/a";
    const mitreTechniqueName = e.attackTechniqueName || "n/a";
    const label = `${e.country} | ${attackKind} | priority ${score.toFixed(1)}`;
    const popup = `
      <strong>${attackKind}</strong><br/>
      Event ID: ${e.id || "n/a"}<br/>
      Source: ${source}<br/>
      IP: ${ipText}<br/>
      Timestamp: ${seenText}<br/>
      Period: ${isLegacy ? "Legacy baseline (2016-2020)" : "Core window (2021-2026/live)"}<br/>
      Location: ${e.lat?.toFixed?.(4)}, ${e.lon?.toFixed?.(4)} (${locationQuality})<br/>
      Threat family: ${e.type}<br/>
      MITRE ATT&CK: ${mitreTactic} | ${mitreTechniqueId} ${mitreTechniqueName}<br/>
      AbuseIPDB: ${abuseScore ?? "n/a"}${abuseReports != null ? ` (reports ${abuseReports})` : ""}<br/>
      NVD: ${nvdCvss != null ? `CVSS ${nvdCvss}` : "n/a"}${nvdCwe ? `, ${nvdCwe}` : ""}<br/>
      Confidence: ${confidencePct}%<br/>
      Priority: ${score.toFixed(1)}
    `;
    marker.bindPopup(popup);
    marker.on("click", () => {
      document.getElementById("selectedHotspot").textContent = label;
    });
  });
}

function redrawMapByThreat() {
  const events = activeThreatKey === "all"
    ? allMapEvents
    : allMapEvents.filter((e) => normalizeThreatKey(e.attackKind || e.type, e.source) === activeThreatKey);
  drawMap(events);
}

function safeLoadThreatLog() {
  try {
    const raw = localStorage.getItem(THREAT_LOG_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.slice(0, THREAT_LOG_MAX);
  } catch {
    return [];
  }
}

function saveThreatLog() {
  try {
    localStorage.setItem(THREAT_LOG_STORAGE_KEY, JSON.stringify(threatLog.slice(0, THREAT_LOG_MAX)));
  } catch {
    return;
  }
}

function safeLoadLiveCache() {
  try {
    const raw = localStorage.getItem(LIVE_CACHE_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    return {
      events: Array.isArray(parsed.events) ? parsed.events : [],
      mapEvents: Array.isArray(parsed.mapEvents) ? parsed.mapEvents : [],
      sourceHealth: parsed.sourceHealth && typeof parsed.sourceHealth === "object" ? parsed.sourceHealth : {},
      updatedAt: parsed.updatedAt || null
    };
  } catch {
    return null;
  }
}

function saveLiveCache(events = [], mapEvents = [], sourceHealth = {}) {
  try {
    const payload = {
      events: Array.isArray(events) ? events.slice(0, 250) : [],
      mapEvents: Array.isArray(mapEvents) ? mapEvents.slice(0, 300) : [],
      sourceHealth: sourceHealth && typeof sourceHealth === "object" ? sourceHealth : {},
      updatedAt: new Date().toISOString()
    };
    localStorage.setItem(LIVE_CACHE_STORAGE_KEY, JSON.stringify(payload));
    lastSyncedAt = payload.updatedAt;
    updateTopBadges();
  } catch {
    return;
  }
}

function buildExpandedFallbackEvents(target = 120) {
  const base = [...(Array.isArray(historicalEvents) ? historicalEvents : []), ...(liveMapEvents || [])];
  if (!base.length) return [];
  const out = [];
  let i = 0;
  while (out.length < target) {
    const src = base[i % base.length];
    const lat = Number(src.lat);
    const lon = Number(src.lon);
    if (Number.isFinite(lat) && Number.isFinite(lon)) {
      const jitterLat = lat + (((i % 7) - 3) * 0.12);
      const jitterLon = lon + ((((i * 3) % 7) - 3) * 0.12);
      out.push({
        ...src,
        id: `${src.id || "fb"}-fb-${i}`,
        source: `${src.source || "fallback"}-fallback`,
        lat: Math.max(-85, Math.min(85, jitterLat)),
        lon: Math.max(-179, Math.min(179, jitterLon)),
        hoursAgo: Number.isFinite(Number(src.hoursAgo)) ? Number(src.hoursAgo) : (i % 48) + 1
      });
    }
    i += 1;
    if (i > target * 20) break;
  }
  return out;
}

function asUtc(ts) {
  if (!ts) return "n/a";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts).slice(0, 19);
  return d.toISOString().replace("T", " ").slice(0, 19);
}

function eventLogEntry(e) {
  const threat = String(e.attackKind || e.type || "Unknown");
  const country = String(e.country || "Unknown");
  const coords = (typeof e.lat === "number" && typeof e.lon === "number")
    ? `${e.lat.toFixed(2)}, ${e.lon.toFixed(2)}`
    : "n/a";
  const eventTime = e.timestamp || e.firstSeen || null;
  return {
    key: `${e.id || "no-id"}|${threat}|${country}|${String(eventTime || "no-time")}`,
    seenAt: new Date().toISOString(),
    eventTime,
    threat,
    location: `${country} (${coords})`
  };
}

function updateThreatLog(events = [], mode = "live") {
  if (!Array.isArray(events) || !events.length) return;
  if (mode === "offline") return;
  const seen = new Set(threatLog.map((x) => x.key));
  for (const e of events) {
    const row = eventLogEntry(e);
    if (seen.has(row.key)) continue;
    threatLog.unshift(row);
    seen.add(row.key);
  }
  if (threatLog.length > THREAT_LOG_MAX) threatLog = threatLog.slice(0, THREAT_LOG_MAX);
  saveThreatLog();
}

function renderThreatLog() {
  const meta = document.getElementById("threatLogMeta");
  const list = document.getElementById("threatLogList");
  if (!meta || !list) return;
  meta.textContent = `${threatLog.length} historical instances`;
  if (!threatLog.length) {
    list.innerHTML = `<div class="threat-log-row"><div class="threat-log-time">-</div><div class="threat-log-threat">No entries yet</div><div class="threat-log-loc">The log will populate as live updates arrive.</div></div>`;
    return;
  }
  list.innerHTML = threatLog
    .slice(0, THREAT_LOG_MAX)
    .map((row) => `
      <div class="threat-log-row">
        <div class="threat-log-time">${asUtc(row.seenAt)}</div>
        <div class="threat-log-threat">${row.threat}</div>
        <div class="threat-log-loc">${row.location}</div>
      </div>
    `)
    .join("");
}

function buildBalancedDisplayEvents(events = []) {
  if (!BALANCED_MAP_MODE || !Array.isArray(events) || events.length < 2) return events;
  const buckets = new Map();
  for (const e of events) {
    const k = normalizeThreatKey(e.attackKind || e.type, e.source);
    if (!buckets.has(k)) buckets.set(k, []);
    buckets.get(k).push(e);
  }
  const orderedKeys = Array.from(buckets.entries())
    .sort((a, b) => b[1].length - a[1].length)
    .map(([k]) => k);
  const out = [];
  let remaining = events.length;
  while (remaining > 0) {
    for (const k of orderedKeys) {
      const list = buckets.get(k);
      if (!list || !list.length) continue;
      out.push(list.shift());
      remaining -= 1;
      if (remaining <= 0) break;
    }
  }
  return out;
}

function getMapModeEvents() {
  const withCoords = Array.isArray(liveMapEvents) ? [...liveMapEvents] : [];
  const seen = new Set(withCoords.map((e) => String(e.id || "")));
  const hasCoords = (e) => Number.isFinite(Number(e?.lat)) && Number.isFinite(Number(e?.lon));
  const hubs = [
    [37.09, -95.71],   // US
    [51.16, 10.45],    // EU
    [20.59, 78.96],    // IN
    [1.35, 103.82],    // SG
    [-14.23, -51.92],  // BR
    [35.86, 104.19],   // CN
    [-25.27, 133.77],  // AU
    [55.37, -3.43]     // GB
  ];
  const alertOnly = (Array.isArray(liveAlertEvents) ? liveAlertEvents : []).filter((e) => !hasCoords(e));
  const projectLimit = 260;
  for (let i = 0; i < alertOnly.length && i < projectLimit; i += 1) {
    const e = alertOnly[i];
    if (seen.has(String(e.id || ""))) continue;
    const hub = hubs[i % hubs.length];
    const jitterLat = (((i % 9) - 4) * 0.28);
    const jitterLon = ((((i * 3) % 9) - 4) * 0.28);
    withCoords.push({
      ...e,
      lat: Number((hub[0] + jitterLat).toFixed(4)),
      lon: Number((hub[1] + jitterLon).toFixed(4)),
      locationQuality: "projected-from-alert (approximate)",
      source: `${e.source || "live"}-projected`
    });
    seen.add(String(e.id || ""));
  }
  return buildBalancedDisplayEvents(withCoords);
}

function getGlossaryEvents() {
  return liveAlertEvents;
}

function updateMapCount() {
  const el = document.getElementById("mapCount");
  if (!el) return;
  el.textContent = `${allMapEvents.length} hotspots · ${liveAlertEvents.length} alerts`;
}

function updateHistoricalSourceNote() {
  const el = document.getElementById("historicalSource");
  if (!el) return;
  el.textContent = "";
}

function renderObservationSummary() {
  const el = document.getElementById("currentOps");
  if (!el) return;
  // Map panel chips should reflect what can be shown on the map (geolocated set),
  // not all alert-only events.
  const events = allMapEvents;
  const counts = events.reduce((acc, e) => {
    const k = normalizeThreatKey(e.attackKind || e.type, e.source);
    acc[k] = (acc[k] || 0) + 1;
    acc.all = (acc.all || 0) + 1;
    return acc;
  }, {});
  const liveThreatChips = attackGlossary
    .filter((g) => g.key !== "all")
    .map((g) => ({ ...g, count: counts[g.key] || 0 }))
    .filter((g) => g.count > 0)
    .sort((a, b) => b.count - a.count);
  el.innerHTML = `
    <button type="button" class="obs-chip selected threat-chip all ${activeThreatKey === "all" ? "active" : ""}" data-threat-key="all" title="All Threats: ${counts.all || 0}" aria-label="All Threats: ${counts.all || 0}">
      ${counts.all || 0}
    </button>
    ${liveThreatChips
      .map(
        (g) =>
          `<button type="button" class="obs-chip selected threat-chip ${activeThreatKey === g.key ? "active" : ""}" data-threat-key="${g.key}" title="${g.type}: ${g.count}" aria-label="${g.type}: ${g.count}" style="border-color:${THREAT_COLORS[g.key] || THREAT_COLORS.unknown};color:${THREAT_COLORS[g.key] || THREAT_COLORS.unknown};">
            <span class="obs-icon" style="--icon-url:url('${THREAT_ICONS[g.key] || THREAT_ICONS.unknown}');--icon-color:${THREAT_COLORS[g.key] || THREAT_COLORS.unknown};" aria-hidden="true"></span>
            ${g.count}
          </button>`
      )
      .join("")}
  `;
  el.querySelectorAll(".threat-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      activeThreatKey = chip.getAttribute("data-threat-key") || "all";
      redrawMapByThreat();
      renderAttackGlossary(getGlossaryEvents());
      renderObservationSummary();
      renderGlossaryDetail();
    });
  });
}

function renderGlossaryDetail() {
  const el = document.getElementById("glossaryDetail");
  if (!el) return;
  el.textContent = "";
}

function setLiveLoading(visible, text = "Loading live feeds...") {
  const el = document.getElementById("liveLoading");
  if (!el) return;
  if (liveLoadingTimeoutId) {
    clearTimeout(liveLoadingTimeoutId);
    liveLoadingTimeoutId = null;
  }
  el.textContent = text;
  el.classList.toggle("hidden", !visible);
  if (visible) {
    liveLoadingTimeoutId = window.setTimeout(() => {
      el.classList.add("hidden");
      liveLoadingTimeoutId = null;
    }, 6000);
  }
}


function renderAlerts(events) {
  const container = document.getElementById("alerts");
  if (!container) return;
  const sourceCounts = events.reduce((acc, e) => {
    const src = String(e.source || "unknown");
    acc[src] = (acc[src] || 0) + 1;
    return acc;
  }, {});
  const ranked = events
    .map((e) => {
      const src = String(e.source || "unknown");
      const base = scoreAlert(e);
      // Penalize overrepresented sources so top cards show category/source diversity.
      const dominancePenalty = Math.min(12, Math.max(0, (sourceCounts[src] || 1) - 3) * 0.5);
      return { ...e, score: base - dominancePenalty };
    })
    .sort((a, b) => b.score - a.score);
  const top = [];
  const usedSources = new Set();
  for (const e of ranked) {
    const src = String(e.source || "unknown");
    if (!usedSources.has(src)) {
      top.push(e);
      usedSources.add(src);
    }
    if (top.length >= 3) break;
  }
  if (top.length < 3) {
    for (const e of ranked) {
      if (top.includes(e)) continue;
      top.push(e);
      if (top.length >= 3) break;
    }
  }

  container.innerHTML = top
    .map(
      (e) => `
      <article class="alert ${severityBand(e.score)}">
        <strong>${e.type} - ${e.country}</strong><br />
        <span class="small">Priority ${e.score.toFixed(1)} | KEV ${e.kev ? "yes" : "no"} | EPSS ${(e.epss * 100).toFixed(1)}%</span>
      </article>`
    )
    .join("") + `<div class="small">Showing top 3 alerts on dashboard (${ranked.length} total in current feed).</div>`;
}

function renderSources() {
  const container = document.getElementById("sources");
  container.innerHTML = sourceCatalog
    .map(
      (s) => `
      <div class="source">
        <div><strong>${s.name}</strong></div>
        <div class="small">${s.type}</div>
        <div><a href="${s.url}" target="_blank" rel="noreferrer">Docs</a></div>
      </div>`
    )
    .join("");
}

function normalizeFeedBadge(statusObj = {}) {
  const status = String(statusObj.status || "");
  const reason = String(statusObj.reason || "");
  if (reason === "ok" && (status.startsWith("ok:") && Number(statusObj.count || 0) > 0)) return { cls: "ok", label: "OK" };
  if (reason === "fallback_on") return { cls: "ok", label: "OK" };
  if (reason === "fallback_off") return { cls: "empty", label: "EMPTY" };
  if (reason === "upstream_empty") return { cls: "empty", label: "EMPTY" };
  if (reason === "throttled") return { cls: "quota", label: "THROTTLED" };
  if (reason === "quota") return { cls: "quota", label: "QUOTA" };
  if (reason === "no_key") return { cls: "nokey", label: "NO KEY" };
  return { cls: "error", label: "ERROR" };
}

function feedStatusHint(sourceName = "", statusObj = {}) {
  const status = String(statusObj.status || "").toLowerCase();
  const reason = String(statusObj.reason || "").toLowerCase();
  const quotaManaged = new Set(["pulsedive", "depsdev", "osv", "cisa_alerts"]);
  if (reason === "throttled") {
    return "Source intentionally throttled to preserve daily request budget.";
  }
  if (reason === "quota" || status.includes("quota")) {
    return "Source temporarily rate-limited; auto-retry later.";
  }
  if (status.includes("forbidden") || status.includes("403")) {
    return "Endpoint denied access (403); not a local outage.";
  }
  if (reason === "upstream_empty") {
    if (status === "ok:0" && quotaManaged.has(String(sourceName || "").toLowerCase())) {
      return "Scheduled skip to preserve daily quota; will run on next cadence.";
    }
    return "Source reachable but no events for current query/time window.";
  }
  if (reason === "fallback_on") {
    return "Local context fallback enabled to maintain map utility.";
  }
  if (reason === "fallback_off") {
    return "Local context fallback is currently inactive.";
  }
  if (reason === "no_key") {
    return "API key not configured for this source.";
  }
  if (reason === "ok") {
    return "Source reachable and returning data.";
  }
  return "Source request or parsing issue.";
}

function renderFeedStatusPanel(sourceHealth = {}) {
  const summaryEl = document.getElementById("feedStatusSummary");
  const gridEl = document.getElementById("feedStatusGrid");
  const chipsEl = document.getElementById("feedStatusChips");
  if (!summaryEl || !gridEl) return;

  const entries = Object.entries(sourceHealth || {});
  if (!entries.length) {
    summaryEl.textContent = liveAlertEvents.length
      ? "Feed health syncing (live events available)."
      : "Feed health syncing...";
    gridEl.innerHTML = "";
    if (chipsEl) chipsEl.innerHTML = `<span class="feed-mini-chip empty">syncing</span>`;
    return;
  }

  const counts = entries.reduce((acc, [, v]) => {
    const b = normalizeFeedBadge(v).cls;
    acc[b] = (acc[b] || 0) + 1;
    return acc;
  }, {});
  const err = counts.error || 0;
  const quota = counts.quota || 0;
  const ok = counts.ok || 0;
  const empty = counts.empty || 0;
  const noKey = counts.nokey || 0;
  summaryEl.textContent = "";
  if (chipsEl) {
    chipsEl.innerHTML = `
      <span class="feed-mini-chip ok">ok:${ok}</span>
      <span class="feed-mini-chip empty">empty:${empty}</span>
      <span class="feed-mini-chip quota">quota:${quota}</span>
      <span class="feed-mini-chip nokey">no key:${noKey}</span>
      <span class="feed-mini-chip error">error:${err}</span>`;
  }

  summaryEl.textContent = "";
  gridEl.innerHTML = entries
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([name, val]) => {
      const badge = normalizeFeedBadge(val);
      const cnt = Number.isFinite(Number(val.count)) ? Number(val.count) : "n/a";
      return `
      <article class="feed-status-item">
        <div class="feed-status-head">
          <strong>${name}</strong>
          <span class="feed-pill ${badge.cls}">${badge.label}</span>
        </div>
        <div class="small">Status: ${val.status || "unknown"}</div>
        <div class="small">Count: ${cnt}</div>
        <div class="small">${feedStatusHint(name, val)}</div>
      </article>`;
    })
    .join("");
}

function setLiveBadge(mode) {
  const badge = document.getElementById("liveBadge");
  if (!badge) return;
  badge.classList.remove("live", "offline", "degraded");
  if (mode === "live") {
    badge.classList.add("live");
    badge.textContent = "LIVE";
    return;
  }
  if (mode === "degraded") {
    badge.classList.add("degraded");
    badge.textContent = liveAlertEvents.length ? "LIVE • LOADING" : "LOADING";
    return;
  }
  badge.classList.add("offline");
  badge.textContent = liveAlertEvents.length ? "LIVE • LOADING" : "OFFLINE";
}

function renderInsights(insights, report = {}, historical = []) {
  const container = document.getElementById("insights");
  if (!container || !Array.isArray(insights) || !insights.length) return;
  const cleanSourceLabel = (s = "") => String(s).replace(/\b20\d{2}\b/g, "").replace(/\s{2,}/g, " ").trim();
  const toThreatKey = (metric = "") => {
    const t = metric.toLowerCase();
    if (t.includes("botnet") || t.includes("c2")) return "botnet_c2";
    if (t.includes("ransom")) return "ransomware";
    if (t.includes("ai-enabled attacks")) return "zero_day";
    if (t.includes("zero-day") || t.includes("vulnerab")) return "zero_day";
    if (t.includes("package") || t.includes("supply") || t.includes("developer")) return "supply_chain";
    if (t.includes("cloud") || t.includes("identity")) return "cloud_iam";
    if (t.includes("voice") || t.includes("fraud")) return "bec";
    if (t.includes("geopolit")) return "ddos";
    if (t.includes("clickfix")) return "phishing";
    if (t.includes("ai")) return "zero_day";
    return "unknown";
  };
  const whyNow = (metric = "") => {
    const t = metric.toLowerCase();
    if (t.includes("breakout")) return "Shrinking defender response window; containment speed is critical.";
    if (t.includes("zero-day")) return "Patch-first models are less effective when exploitation starts pre-disclosure.";
    if (t.includes("package") || t.includes("supply")) return "Third-party dependencies become high-leverage initial access paths.";
    if (t.includes("developer")) return "Secret sprawl increases identity and cloud compromise risk.";
    if (t.includes("cloud")) return "Identity-centric controls need continuous hardening and session monitoring.";
    if (t.includes("geopolit")) return "Geopolitical attack planning is rising into 2026.";
    if (t.includes("fraud") || t.includes("voice")) return "Deepfake-enabled social engineering pressures finance workflows.";
    return "Sustained attacker adaptation; control tuning and prioritization required.";
  };
  const normalizeForBar = (metric = "", value = 0) => {
    const t = metric.toLowerCase();
    const v = Number(value) || 0;
    if (t.includes("breakout")) return Math.max(0, 100 - Math.min(v, 100));
    if (t.includes("npm")) return Math.min(100, (v / 12000) * 100);
    if (t.includes("loss")) return Math.min(100, (v / 300) * 100);
    return Math.min(100, v);
  };
  const formatValue = (m) => {
    const t = String(m.metric || "").toLowerCase();
    const n = Number(m.value);
    if (t.includes("voice") || String(m.unit || "").toLowerCase().includes("usd")) return `$${Math.round(n)}M`;
    if (t.includes("npm") && n >= 1000) return `${Math.round(n / 1000)}K`;
    if (String(m.unit || "").includes("%") || t.includes("yoy") || t.includes("increase")) return `${Math.round(n)}%`;
    if (t.includes("breakout")) return `${Math.round(n)}m`;
    return `${m.value}`;
  };
  const model = insights.map((m) => {
    const threatKey = toThreatKey(m.metric);
    const impact = Math.round(normalizeForBar(m.metric, m.value));
    return { ...m, threatKey, impact, displayValue: formatValue(m), why: whyNow(m.metric) };
  });
  const matrixSeverity = (score) => (score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : "MEDIUM");
  const pickMetric = (patterns = []) =>
    model.find((m) => {
      const metric = String(m.metric || "").toLowerCase();
      return patterns.some((p) => metric.includes(p));
    });
  const pickMaxByThreat = (threatKey) =>
    [...model]
      .filter((m) => m.threatKey === threatKey && String(m.displayValue).includes("%"))
      .sort((a, b) => (Number(b.value) || 0) - (Number(a.value) || 0))[0];
  const pctRowsBase = [
    {
      label: "ClickFix activity",
      sourceLabel: "Check Point 2026",
      ...(pickMetric(["clickfix"]) || { value: 500, displayValue: "500%", impact: 100, threatKey: "phishing" }),
      threatKey: "phishing"
    },
    {
      label: "Botnet C2",
      sourceLabel: "CrowdStrike 2026",
      ...(pickMetric(["botnet", "c2"]) || { value: 500, displayValue: "500%", impact: 100, threatKey: "botnet_c2" }),
      threatKey: "botnet_c2"
    },
    {
      label: "AI-Enabled Attacks",
      sourceLabel: "CrowdStrike 2026",
      ...(pickMetric(["ai-enabled attacks"]) || { value: 89, displayValue: "89%", impact: 89, threatKey: "zero_day" }),
      threatKey: "zero_day"
    },
    {
      label: "Supply Chain Compromise",
      sourceLabel: "Software Supply Chain 2026",
      ...(pickMaxByThreat("supply_chain") || { value: 73, displayValue: "73%", impact: 73, threatKey: "supply_chain" }),
      threatKey: "supply_chain"
    },
    {
      label: "KEV Exploitation",
      sourceLabel: "CrowdStrike 2026",
      ...(pickMetric(["zero-day exploitation before disclosure"]) || { value: 42, displayValue: "42%", impact: 42, threatKey: "kev" }),
      threatKey: "kev"
    },
    {
      label: "Cloud / IAM Abuse",
      sourceLabel: "CrowdStrike 2026",
      ...(pickMetric(["cloud-conscious intrusions", "cloud", "identity"]) || { value: 37, displayValue: "37%", impact: 37, threatKey: "cloud_iam" }),
      threatKey: "cloud_iam"
    },
    {
      label: "Ransomware",
      sourceLabel: "2026 Cyber Security Report",
      ...(pickMetric(["ransomware"]) || { value: 34, displayValue: "34%", impact: 34, threatKey: "ransomware" }),
      threatKey: "ransomware"
    }
  ];
  const allPercentRows = model
    .filter((m) => String(m.displayValue).includes("%"))
    .map((m) => ({
      ...m,
      label: m.metric,
      sourceLabel: m.source
    }))
    .sort((a, b) => (Number(b.value) || 0) - (Number(a.value) || 0));
  const pctRowsMap = new Map();
  [...pctRowsBase, ...allPercentRows].forEach((row) => {
    const key = String(row.label || row.metric || "").toLowerCase().trim();
    if (!key) return;
    if (!pctRowsMap.has(key)) pctRowsMap.set(key, row);
  });
  const dedupedPctRows = Array.from(pctRowsMap.values());
  const aiRows = dedupedPctRows.filter((r) => {
    const label = String(r.label || r.metric || "").toLowerCase();
    return label.includes("ai");
  });
  const nonAiRows = dedupedPctRows.filter((r) => {
    const label = String(r.label || r.metric || "").toLowerCase();
    return !label.includes("ai") && !label.includes("geopolit");
  });
  const aiComposite = aiRows.length
    ? (() => {
        const strongest = [...aiRows].sort((a, b) => (Number(b.value) || 0) - (Number(a.value) || 0))[0];
        return {
          ...strongest,
          label: "AI Threat Acceleration",
          sourceLabel: "CrowdStrike + WEF",
          explanation: "Combines AI-enabled attack growth with AI vulnerability risk signals.",
          threatKey: "zero_day"
        };
      })()
    : null;
  const tieBreakOrder = [
    "botnet c2",
    "clickfix activity",
    "ai threat acceleration",
    "supply chain compromise",
    "kev exploitation",
    "cloud / iam abuse",
    "ransomware"
  ];
  const tieBreakIndex = (row) => {
    const key = String(row.label || row.metric || "").toLowerCase().trim();
    const idx = tieBreakOrder.indexOf(key);
    return idx === -1 ? Number.MAX_SAFE_INTEGER : idx;
  };
  const pctRows = (aiComposite ? [aiComposite, ...nonAiRows] : nonAiRows).sort((a, b) => {
    const diff = (Number(b.value) || 0) - (Number(a.value) || 0);
    if (diff !== 0) return diff;
    return tieBreakIndex(a) - tieBreakIndex(b);
  });
  const aggregateRows = (rows) => {
    const out = [];
    const used = new Set();
    const pushGroup = (name, matcher, threatKey, sourceLabel) => {
      const group = rows.filter((r) => !used.has(r) && matcher(r));
      if (!group.length) return;
      group.forEach((r) => used.add(r));
      const strongest = [...group].sort((a, b) => (Number(b.value) || 0) - (Number(a.value) || 0))[0];
      out.push({
        ...strongest,
        label: name,
        threatKey,
        sourceLabel,
        explanation:
          group.length > 1
            ? `Includes: ${group.map((g) => g.label || g.metric).join(", ")}.`
            : strongest.explanation
      });
    };
    const labelOf = (r) => String(r.label || r.metric || "").toLowerCase();
    pushGroup("Botnet C2", (r) => r.threatKey === "botnet_c2" || labelOf(r).includes("botnet"), "botnet_c2", "CrowdStrike");
    pushGroup("Software Supply Chain", (r) => r.threatKey === "supply_chain", "supply_chain", "Software Supply Chain");
    pushGroup("Exploitation Pressure", (r) => r.threatKey === "kev" || labelOf(r).includes("zero-day"), "kev", "CrowdStrike");
    pushGroup("Cloud / IAM Abuse", (r) => r.threatKey === "cloud_iam", "cloud_iam", "CrowdStrike");
    pushGroup("Ransomware", (r) => r.threatKey === "ransomware" || labelOf(r).includes("ransomware"), "ransomware", "Cyber Security Report");
    rows.forEach((r) => {
      if (!used.has(r)) out.push(r);
    });
    return out;
  };
  const pctRowsMerged = aggregateRows(pctRows).sort((a, b) => (Number(b.value) || 0) - (Number(a.value) || 0));
  const pctColorForRow = (row) => {
    const label = String(row.label || row.metric || "").toLowerCase();
    // Fixed panel palette by category label for visual consistency.
    if (label.includes("botnet")) return "#14b8a6"; // teal
    if (label.includes("clickfix")) return "#84cc16"; // lime
    if (label.includes("ai threat")) return "#ec4899"; // magenta
    if (label.includes("software supply chain")) return "#6366f1"; // indigo
    if (label.includes("exploitation pressure")) return "#ffd166"; // glossary KEV yellow
    if (label.includes("cloud / iam")) return "#38bdf8"; // sky
    if (label.includes("ransomware")) return "#ff4d6d"; // rose
    return THREAT_COLORS[row.threatKey] || THREAT_COLORS.unknown;
  };
  const matrixRows = [...model].sort((a, b) => b.impact - a.impact).slice(0, 7);

  void report;
  void historical;

  container.innerHTML = `
    <section class="report-section">
      <div class="tl-section-title">Threat baseline and change</div>
      <div class="traj-story">
        <section class="traj-panel traj-panel-compact">
          <div class="traj-panel-title">Historical Baseline (2021-2026)</div>
          <section class="calm-block">
            <div class="panel-head calm-head">
              <h2>Threat Category Mix (2021-2026)</h2>
              <button class="toggle-btn calm-toggle" type="button" data-target="threatMixWrap" aria-expanded="false">+</button>
            </div>
            <div id="threatMixWrap" class="collapsed">
              <section class="traj-panel">
              <div class="traj-baseline-row">
                <div class="traj-donut-wrap traj-donut-right">
                  <canvas id="baselineDonut" width="300" height="240"></canvas>
                </div>
                <div id="baselineLegend" class="traj-legend"></div>
              </div>
              </section>
            </div>
          </section>
        </section>
        <section class="traj-panel traj-panel-compact">
          <div class="traj-panel-title">Recent Changes (2025-2026)</div>
          <section class="calm-block subsection-block" style="margin-top:12px;">
            <div class="panel-head calm-head">
              <h2>Threat Changes by Percentage (2025-2026)</h2>
              <button class="toggle-btn calm-toggle" type="button" data-target="pctChangesWrap" aria-expanded="false">+</button>
            </div>
            <div id="pctChangesWrap" class="collapsed">
            <div class="tl-strip" style="padding:0;grid-template-columns:1fr;margin:2px 0 10px;">
              <article class="tl-card">
                <div class="tl-label">Threat acceleration across AI, botnet, and geopolitical activity</div>
                <div class="small">AI-enabled and botnet/C2 activity rose sharply; geopolitically motivated cyberattack planning also increased, linked to ongoing political instability.</div>
              </article>
            </div>
            <div class="tl-bars" style="margin-top:8px;grid-template-columns:1fr;">
              ${pctRowsMerged
                .map(
                  (m) => `
                  <div class="tl-bar-row" style="--tl-color:${pctColorForRow(m)};">
                    <div class="tl-bar-head">
                      <span>${m.label || m.metric}</span>
                      <strong>${m.displayValue}</strong>
                    </div>
                    <div class="small">${cleanSourceLabel(m.sourceLabel || m.source)} (2025-2026)</div>
                    ${m.explanation ? `<div class="small">${m.explanation}</div>` : ""}
                    <div class="tl-bar-track"><span class="tl-bar-fill" style="width:${m.impact}%;"></span></div>
                  </div>`
                )
                .join("")}
            </div>
            </div>
          </section>
          <section class="calm-block subsection-block advanced-analytics" style="margin-top:10px;">
            <div class="panel-head calm-head">
              <h2>Deep Dive: Radar and Matrix</h2>
              <button class="toggle-btn calm-toggle" type="button" data-target="deepDiveWrap" aria-expanded="false">+</button>
            </div>
            <div id="deepDiveWrap" class="collapsed">
            <div class="tl-bottom-grid">
              <div class="tl-panel">
                <div class="tl-panel-title">Threat vector radar</div>
                <canvas id="tlRadar" width="520" height="380"></canvas>
              </div>
              <div class="tl-panel">
                <div class="tl-panel-title">Threat intelligence matrix</div>
                <div class="tl-matrix-wrap">
                  <table class="tl-matrix">
                    <thead>
                      <tr><th>Threat Vector</th><th>Severity</th><th>Impact</th><th>Source</th></tr>
                    </thead>
                    <tbody>
                      ${matrixRows
                        .map(
                          (m) => `
                          <tr>
                            <td><span class="tl-dot" style="background:${THREAT_COLORS[m.threatKey] || THREAT_COLORS.unknown};"></span>${m.metric}</td>
                            <td class="tl-sev">${matrixSeverity(m.impact)}</td>
                            <td><div class="tl-impact-track"><span style="width:${m.impact}%;background:${THREAT_COLORS[m.threatKey] || THREAT_COLORS.unknown};"></span></div></td>
                            <td>${m.source}</td>
                          </tr>`
                        )
                        .join("")}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
            </div>
          </section>
        </section>
      </div>
    </section>
    ${renderNetscoutAtlas(report)}
  `;

  setTimeout(() => {
    document.querySelectorAll(".tl-bar-fill").forEach((el) => el.classList.add("animated"));
  }, 200);

  drawThreatRadar(
    "tlRadar",
    (() => {
      const shortLabel = (metric = "") => {
        const t = String(metric).toLowerCase();
        if (t.includes("clickfix")) return "ClickFix";
        if (t.includes("ai-enabled attacks")) return "AI attacks";
        if (t.includes("ai vulnerabil")) return "AI vulns";
        if (t.includes("voice-enabled")) return "Voice";
        if (t.includes("malicious npm")) return "npm";
        if (t.includes("malicious open-source")) return "OSS";
        return metric.length > 14 ? `${metric.slice(0, 14)}…` : metric;
      };
      return matrixRows.slice(0, 6).map((m) => ({
        label: shortLabel(m.metric),
        value: Math.max(0.08, Math.min(1, m.impact / 100)),
        color: THREAT_COLORS[m.threatKey] || THREAT_COLORS.unknown
      }));
    })()
  );
  drawBaselineTrajectory();
  container.querySelectorAll(".calm-toggle[data-target]").forEach((btn) => {
    const targetId = btn.getAttribute("data-target");
    const wrap = targetId ? document.getElementById(targetId) : null;
    if (!wrap) return;
    const head = btn.closest(".calm-head");
    const sync = () => {
      const collapsed = wrap.classList.contains("collapsed");
      btn.textContent = collapsed ? "+" : "−";
      btn.setAttribute("aria-expanded", collapsed ? "false" : "true");
    };
    const toggle = () => {
      wrap.classList.toggle("collapsed");
      sync();
    };
    sync();
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      toggle();
    });
    if (head) {
      head.style.cursor = "pointer";
      head.addEventListener("click", () => toggle());
    }
  });
  setTimeout(() => {
    document.querySelectorAll(".tl-bar-fill").forEach((el) => el.classList.add("animated"));
  }, 250);
  setTimeout(() => {
    document.querySelectorAll(".ns-rbar-fill").forEach((el) => el.classList.add("go"));
  }, 320);
}

function renderNetscoutAtlas(report = {}) {
  const meta = report.meta || {};
  const kpis = Array.isArray(report.kpis) ? report.kpis : [];
  const regional = Array.isArray(report.regional_attacks) ? report.regional_attacks : [];
  const critical = Array.isArray(report.critical_infra) ? report.critical_infra : [];
  const totalRegional = regional.reduce((acc, r) => acc + (Number(r.value) || 0), 0) || 1;
  const regionColor = {
    EMEA: "#00ffb3",
    APAC: "#00b8ff",
    "North America": "#ff6b35",
    LATAM: "#c77dff"
  };
  const regionPos = {
    EMEA: { left: 49, top: 42, outer: 110, inner: 80, short: "EMEA" },
    APAC: { left: 77, top: 44, outer: 88, inner: 64, short: "APAC" },
    "North America": { left: 17, top: 35, outer: 72, inner: 52, short: "NOAM" },
    LATAM: { left: 22, top: 65, outer: 60, inner: 44, short: "LATAM" }
  };
  const topRegional = [...regional].sort((a, b) => (Number(b.value) || 0) - (Number(a.value) || 0));
  const maxRegion = Number(topRegional[0]?.value || 1);
  const byLabel = (name, fallback = "n/a") => (kpis.find((k) => String(k.label || "").toLowerCase() === name.toLowerCase())?.value || fallback);

  return `
    <section class="report-section ns-wrap">
      <div class="ns-header">
        <div>
          <h3 class="ns-title">GLOBAL <em>DDOS</em> THREAT INTELLIGENCE</h3>
          <div class="ns-sub">ISSUE 16 · WINDOW: ${meta.window || "2H 2025"} · PUBLISHED: ${meta.published || "2026-02"} · ${byLabel("Countries impacted", "203")} COUNTRIES MONITORED</div>
        </div>
        <div class="ns-meta">
          <div class="ns-source">Source: DDoS Threat Intelligence Report<br>Issue 16 Baseline</div>
          <div class="ns-live">INTELLIGENCE ACTIVE</div>
        </div>
      </div>

      <div class="ns-kpi-strip">
        <article class="ns-kpi"><div class="ns-kpi-num">${byLabel("Total attacks", "8,088,463")}</div><div class="ns-kpi-label">Total DDoS Attacks</div></article>
        <article class="ns-kpi"><div class="ns-kpi-num">${byLabel("Countries impacted", "203")}</div><div class="ns-kpi-label">Countries Impacted</div></article>
        <article class="ns-kpi"><div class="ns-kpi-num">${String(byLabel("Peak demonstrated capacity", "30 Tbps / 4 Gpps")).split("/")[0].trim()}</div><div class="ns-kpi-label">Peak Demonstrated Capacity</div></article>
        <article class="ns-kpi"><div class="ns-kpi-num">${byLabel("NTP alerts", "45,000+")}</div><div class="ns-kpi-label">NTP Alerts Triggered</div></article>
        <article class="ns-kpi"><div class="ns-kpi-num">${byLabel("DNS root notable events", "38")}</div><div class="ns-kpi-label">DNS Root Notable Events</div></article>
      </div>

      <div class="ns-main-grid">
        <section class="ns-panel">
          <div class="ns-panel-title">Global Attack Distribution — Regional Heat</div>
          <div class="ns-map-container">
            <svg class="ns-world-map" viewBox="0 0 1000 500" xmlns="http://www.w3.org/2000/svg" fill="#4a7fa5" stroke="#0a1a2e" stroke-width="1">
              <path d="M80,60 L200,50 L230,80 L220,140 L190,180 L160,200 L130,220 L100,200 L70,160 L60,120 Z"/><path d="M160,200 L190,200 L195,240 L175,260 L155,240 Z"/><path d="M160,260 L220,240 L260,260 L280,320 L270,390 L240,430 L200,440 L170,400 L150,350 L145,300 Z"/><path d="M420,40 L520,35 L540,70 L530,110 L500,120 L470,130 L440,120 L420,100 L410,70 Z"/><path d="M440,20 L470,10 L490,25 L480,55 L455,60 L440,40 Z"/><path d="M420,140 L530,130 L560,160 L570,220 L560,300 L540,370 L500,410 L460,400 L430,360 L410,280 L400,200 Z"/><path d="M540,110 L610,100 L630,140 L610,170 L570,165 L545,145 Z"/><path d="M500,20 L700,10 L750,40 L740,90 L700,100 L640,95 L580,85 L530,70 L510,45 Z"/><path d="M620,110 L710,100 L730,140 L720,190 L690,210 L660,200 L630,170 L615,140 Z"/><path d="M710,60 L820,50 L850,90 L840,140 L800,160 L760,150 L730,120 L715,90 Z"/><path d="M730,170 L800,165 L820,200 L800,230 L770,225 L745,200 Z"/><path d="M760,310 L870,300 L900,340 L890,390 L850,410 L800,400 L765,370 L750,340 Z"/><path d="M840,90 L860,80 L875,100 L865,125 L845,120 Z"/><path d="M400,50 L415,45 L418,70 L405,75 L398,60 Z"/><path d="M230,10 L310,5 L320,30 L300,50 L260,55 L235,35 Z"/><path d="M740,250 L780,245 L800,260 L790,275 L760,270 Z M800,255 L840,250 L855,265 L840,278 L808,272 Z"/>
            </svg>
            <div class="ns-map-overlay">
              ${topRegional
                .map((r) => {
                  const p = regionPos[r.region] || { left: 50, top: 50, outer: 68, inner: 48, short: r.region };
                  const pct = Math.round(((Number(r.value) || 0) / totalRegional) * 100);
                  const color = regionColor[r.region] || "#00b8ff";
                  return `<div class="ns-region-bubble" style="left:${p.left}%;top:${p.top}%">
                    <div class="ns-bubble-ring" style="width:${p.outer}px;height:${p.outer}px;background:color-mix(in srgb, ${color} 12%, transparent);border-color:color-mix(in srgb, ${color} 45%, transparent);box-shadow:0 0 22px color-mix(in srgb, ${color} 25%, transparent);">
                      <div class="ns-bubble-inner" style="width:${p.inner}px;height:${p.inner}px;background:color-mix(in srgb, ${color} 18%, transparent);">
                        <div class="ns-bubble-pct" style="color:${color};">${pct}%</div>
                        <div class="ns-bubble-name" style="color:${color};">${p.short}</div>
                        <div class="ns-bubble-attacks" style="color:${color};">${(Number(r.value) || 0).toLocaleString()}</div>
                      </div>
                    </div>
                  </div>`;
                })
                .join("")}
            </div>
          </div>
        </section>

        <section class="ns-panel">
          <div class="ns-panel-title">Attack Volume by Region</div>
          <div class="ns-region-bars">
            ${topRegional
              .map((r) => {
                const pct = Math.round(((Number(r.value) || 0) / totalRegional) * 100);
                const w = Math.max(10, Math.round(((Number(r.value) || 0) / maxRegion) * 100));
                const color = regionColor[r.region] || "#00b8ff";
                return `<div class="ns-rbar-item"><div class="ns-rbar-header"><div class="ns-rbar-name" style="color:${color};">${r.region}</div><div class="ns-rbar-count">${(Number(r.value) || 0).toLocaleString()} attacks</div></div><div class="ns-rbar-track"><div class="ns-rbar-fill" style="width:${w}%;background:${color};box-shadow:0 0 8px ${color};"></div></div><div class="ns-rbar-pct" style="color:${color};">${pct}%</div></div>`;
              })
              .join("")}
            <details class="ns-subdetails">
              <summary>Capacity Reference</summary>
              <div class="ns-cap-ref ns-subcontent">
                <div class="ns-cap-row"><div class="ns-cap-num yellow">${String(byLabel("Peak demonstrated capacity", "30 Tbps / 4 Gpps")).split("/")[0].trim()}</div><div class="ns-cap-text">Peak demonstrated attack capacity</div></div>
                <div class="ns-cap-row"><div class="ns-cap-num orange">${String(byLabel("Peak demonstrated capacity", "30 Tbps / 4 Gpps")).split("/")[1]?.trim() || "4 Gpps"}</div><div class="ns-cap-text">Peak packets-per-second demonstrated</div></div>
              </div>
            </details>
            <details class="ns-subdetails">
              <summary>Critical Infrastructure Events</summary>
              <div class="ns-cap-ref ns-subcontent">
                <div class="ns-infra-cards">
                  ${critical
                    .map((c, i) => `<article class="ns-infra-card ${i === 0 ? "dns" : "ntp"}"><div class="ns-infra-type">${c.metric}</div><div class="ns-infra-metric">${i === 0 ? "21 Gbps" : "45,000+"}</div><div class="ns-infra-desc">${c.value}</div></article>`)
                    .join("")}
                </div>
                <div class="ns-surface-mix">
                  <div class="ns-mix-title">Attack Surface Mix (Estimated)</div>
                  <div class="ns-mix-row"><span>Volumetric / Flood</span><strong>62%</strong><div class="ns-mix-track"><span style="width:62%;background:#00ffb3"></span></div></div>
                  <div class="ns-mix-row"><span>Protocol / Amplification</span><strong>24%</strong><div class="ns-mix-track"><span style="width:24%;background:#00b8ff"></span></div></div>
                  <div class="ns-mix-row"><span>Application Layer (L7)</span><strong>14%</strong><div class="ns-mix-track"><span style="width:14%;background:#ffd60a"></span></div></div>
                </div>
              </div>
            </details>
          </div>
        </section>
      </div>
      <div class="ns-footer">SOURCE: ${meta.source || "DDoS Threat Intelligence Report"} · ${meta.window || "2H 2025"} · PUBLISHED ${meta.published || "2026-02"}</div>
    </section>
  `;
}

function drawThreatRadar(canvasId, threats) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !canvas.getContext || !Array.isArray(threats) || !threats.length) return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  const rect = canvas.getBoundingClientRect();
  const cssWidth = Math.max(1, Math.round(rect.width || canvas.width || 520));
  const cssHeight = Math.max(1, Math.round((rect.height || canvas.height || 380)));
  const dpr = window.devicePixelRatio || 1;
  const targetWidth = Math.round(cssWidth * dpr);
  const targetHeight = Math.round(cssHeight * dpr);
  if (canvas.width !== targetWidth || canvas.height !== targetHeight) {
    canvas.width = targetWidth;
    canvas.height = targetHeight;
  }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssWidth, cssHeight);
  const cx = cssWidth / 2;
  const cy = cssHeight / 2;
  const R = Math.min(cssWidth, cssHeight) * 0.37;
  const N = threats.length;
  const angle = (i) => (Math.PI * 2 * i / N) - Math.PI / 2;
  const polarPoint = (i, r) => [cx + r * Math.cos(angle(i)), cy + r * Math.sin(angle(i))];

  for (let ring = 1; ring <= 4; ring += 1) {
    ctx.beginPath();
    for (let i = 0; i < N; i += 1) {
      const [x, y] = polarPoint(i, (R * ring) / 4);
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    }
    ctx.closePath();
    ctx.strokeStyle = "rgba(50, 93, 132, 0.8)";
    ctx.lineWidth = 1.2;
    ctx.stroke();
  }

  for (let i = 0; i < N; i += 1) {
    const [x, y] = polarPoint(i, R);
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(x, y);
    ctx.strokeStyle = "rgba(50, 93, 132, 0.62)";
    ctx.lineWidth = 1.1;
    ctx.stroke();
  }

  ctx.beginPath();
  threats.forEach((t, i) => {
    const [x, y] = polarPoint(i, R * t.value);
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.closePath();
  ctx.fillStyle = "rgba(0, 207, 255, 0.12)";
  ctx.fill();
  ctx.strokeStyle = "rgba(78, 214, 255, 0.9)";
  ctx.lineWidth = 2.2;
  ctx.stroke();

  threats.forEach((t, i) => {
    const [x, y] = polarPoint(i, R * t.value);
    ctx.beginPath();
    ctx.arc(x, y, 6, 0, Math.PI * 2);
    ctx.fillStyle = t.color;
    ctx.fill();
    ctx.strokeStyle = "rgba(7, 17, 27, 0.85)";
    ctx.lineWidth = 2;
    ctx.stroke();
  });

  ctx.font = '600 13px "Space Grotesk", sans-serif';
  ctx.textAlign = "center";
  ctx.fillStyle = "#d2e8fa";
  threats.forEach((t, i) => {
    const [x, y] = polarPoint(i, R + 36);
    const max = 16;
    const clean = t.label.length > max ? `${t.label.slice(0, max - 1)}…` : t.label;
    ctx.fillText(clean, x, y + 4);
  });
}

function drawBaselineTrajectory() {
  const canvas = document.getElementById("baselineDonut");
  const legendEl = document.getElementById("baselineLegend");
  const cardsEl = document.getElementById("baselineDeltaCards");
  if (!canvas || !legendEl || !canvas.getContext) return;
  const threats = [
    { key: "ransomware", name: "Ransomware", share: 17, color: THREAT_COLORS.ransomware, events2025: 2, delta: 34, base26: 85, base25: 63, note: "Double-extortion activity remains persistent." },
    { key: "credential_theft", name: "Credential Theft", share: 17, color: THREAT_COLORS.credential_theft, events2025: 2, delta: 28, base26: 78, base25: 61, note: "Infostealer activity and token abuse remain high." },
    { key: "supply_chain", name: "Supply Chain Compromise", share: 17, color: THREAT_COLORS.supply_chain, events2025: 2, delta: 73, base26: 95, base25: 55, note: "Malicious OSS package pressure remains elevated." },
    { key: "ddos", name: "DDoS", share: 8, color: THREAT_COLORS.ddos, events2025: 1, delta: 12, base26: 48, base25: 43, note: "Volumetric disruption campaigns stay active." },
    { key: "botnet_c2", name: "Botnet C2", share: 8, color: THREAT_COLORS.botnet_c2, events2025: 1, delta: 500, base26: 100, base25: 17, note: "Automation-led C2 signaling increased sharply." },
    { key: "kev", name: "KEV Exploitation", share: 8, color: THREAT_COLORS.kev, events2025: 1, delta: 42, base26: 82, base25: 58, note: "Pre-disclosure exploitation pressure persists." },
    { key: "phishing", name: "Phishing / Social Eng.", share: 8, color: THREAT_COLORS.phishing, events2025: 1, delta: 18, base26: 55, base25: 47, note: "AI-assisted social engineering remains effective." },
    { key: "cloud_iam", name: "Cloud / IAM Abuse", share: 8, color: THREAT_COLORS.cloud_iam, events2025: 1, delta: 37, base26: 77, base25: 56, note: "Identity-centric intrusion paths continue rising." },
    { key: "zero_day", name: "AI-Enabled Attacks", share: 9, color: THREAT_COLORS.zero_day, events2025: 1, delta: 89, base26: 100, base25: 53, note: "LLM-assisted recon/evasion reached critical momentum." }
  ];

  const ctx = canvas.getContext("2d");
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  const cx = canvas.width / 2;
  const cy = canvas.height / 2;
  const outerR = Math.min(canvas.width, canvas.height) * 0.46;
  const innerR = outerR * 0.62;
  const total = threats.reduce((s, t) => s + t.share, 0) || 1;
  let start = -Math.PI / 2;
  const gap = 0.025;
  threats.forEach((t) => {
    const slice = (t.share / total) * Math.PI * 2;
    const end = start + slice - gap;
    ctx.beginPath();
    ctx.moveTo(cx + outerR * Math.cos(start + gap / 2), cy + outerR * Math.sin(start + gap / 2));
    ctx.arc(cx, cy, outerR, start + gap / 2, end);
    ctx.arc(cx, cy, innerR, end, start + gap / 2, true);
    ctx.closePath();
    ctx.fillStyle = t.color;
    ctx.fill();
    start += slice;
  });

  legendEl.innerHTML = threats
    .map((t) => `<div class="traj-legend-item"><span class="traj-legend-pct" style="color:${t.color};">${t.share}%</span><span class="traj-legend-name">${t.name}</span></div>`)
    .join("");

  if (cardsEl) {
    cardsEl.innerHTML = threats
      .sort((a, b) => b.delta - a.delta)
      .slice(0, 6)
      .map((t) => `<article class="traj-delta-card" style="border-left-color:${t.color};">
        <div>
          <div class="traj-threat">${t.name}</div>
          <div class="traj-base">${t.events2025} tracked event${t.events2025 > 1 ? "s" : ""} (2025 baseline) · ${t.note}</div>
        </div>
        <div class="traj-delta"><div class="traj-delta-badge" style="color:${t.color};">+${t.delta}%</div><div class="traj-delta-label">YoY 2025→26</div></div>
        <div class="traj-spark-row">
          <span class="traj-spark-label">2025</span>
          <div class="traj-spark-track"><span class="traj-spark-2025" style="width:${t.base25}%; background:${t.color};"></span><span class="traj-spark-2026" style="width:0%; background:${t.color};" data-target="${t.base26}"></span></div>
          <span class="traj-spark-label">2026 ${t.base26 === 100 ? "MAX" : `${t.base26}%`}</span>
        </div>
      </article>`)
      .join("");

    setTimeout(() => {
      document.querySelectorAll(".traj-spark-2026").forEach((el) => {
        el.style.width = `${el.getAttribute("data-target") || 0}%`;
      });
    }, 260);
  }
}

function renderReportIntel(report = {}) {
  const container = document.getElementById("insights");
  if (!container) return;
  const kpis = report.kpis || [];
  const regional = report.regional_attacks || [];
  const critical = report.critical_infra || [];
  const actors = report.threat_actors || [];
  const meta = report.meta || {};
  const totalRegional = regional.reduce((acc, r) => acc + (Number(r.value) || 0), 0) || 1;

  container.innerHTML = `
    <div class="report-meta">
      Source: ${meta.source || "NETSCOUT"} | Window: ${meta.window || "2H 2025"} | Published: ${meta.published || "n/a"}
    </div>
    <section class="report-section">
      <h3>Global KPI Strip</h3>
      <div class="report-kpi-grid">
        ${kpis
          .map(
            (k) => `
            <article class="report-kpi">
              <div class="report-kpi-value">${k.value}</div>
              <div class="report-kpi-label">${k.label}</div>
            </article>`
          )
          .join("")}
      </div>
    </section>
    <section class="report-section">
      <div class="panel-head-actions">
        <h3>Baseline Context</h3>
      </div>
      <div id="baselineContextWrap">
        <section class="report-section">
          <h3>Regional Distribution</h3>
          <div class="tl-bars">
            ${regional
              .map((r) => {
                const pct = Math.round(((Number(r.value) || 0) / totalRegional) * 100);
                return `
                  <div class="tl-bar-row" style="--tl-color:#19d2a3;">
                    <div class="tl-bar-head"><span>${r.region}</span><strong>${pct}%</strong></div>
                    <div class="tl-bar-track"><span class="tl-bar-fill" style="width:${pct}%;"></span></div>
                    <div class="small">${r.value.toLocaleString()} observed attacks</div>
                  </div>`;
              })
              .join("")}
          </div>
        </section>
        <section class="report-section">
          <h3>Critical Infrastructure</h3>
          <div class="tl-strip tl-strip-2">
            ${critical
              .map(
                (c, i) => `
                <article class="tl-card" style="--tl-color:${i === 0 ? "#ffd166" : "#ff7c2a"};">
                  <div class="tl-label">${c.metric}</div>
                  <div class="small" style="margin-top:4px;">${c.value}</div>
                </article>`
              )
              .join("")}
          </div>
        </section>
        <section class="report-section">
          <h3>Threat Actor Activity</h3>
          <div class="tl-strip tl-strip-3">
            ${actors
              .map(
                (a, i) => `
                <article class="tl-card" style="--tl-color:${i === 0 ? "#ff4757" : i === 1 ? "#9b6dff" : "#00cfff"};">
                  <div class="tl-label">${a.actor}</div>
                  <div class="small">${a.detail}</div>
                  <div class="tl-source">${a.confidence}</div>
                </article>`
              )
              .join("")}
          </div>
        </section>
        <section class="report-section">
          <h3>Historical (5-year) Threat Baseline</h3>
          <div class="small">Window fixed to 2021-2026 (share by category).</div>
          <div id="historicalBaselineBars" class="tl-bars" style="margin-top:8px;"></div>
        </section>
      </div>
    </section>
  `;
}

function renderHistoricalAnalytics(events = []) {
  const barsEl = document.getElementById("historicalBaselineBars");
  if (!barsEl) return;
  const fiveYear = events.filter((e) => (e.timestamp || "").slice(0, 10) >= "2021-01-01");
  const counts = fiveYear.reduce((acc, e) => {
    const k = normalizeThreatKey(e.attackKind || e.type, e.source);
    acc[k] = (acc[k] || 0) + 1;
    acc.total = (acc.total || 0) + 1;
    return acc;
  }, {});
  const rows = attackGlossary
    .filter((g) => g.key !== "all")
    .map((g) => ({ key: g.key, type: g.type, count: counts[g.key] || 0 }))
    .filter((g) => g.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);
  const total = counts.total || 1;
  barsEl.innerHTML = rows
    .map((r) => {
      const pct = Math.round((r.count / total) * 100);
      return `
        <div class="tl-bar-row" style="--tl-color:${THREAT_COLORS[r.key] || THREAT_COLORS.unknown};">
          <div class="tl-bar-head"><span>${r.type}</span><strong>${pct}%</strong></div>
          <div class="tl-bar-track"><span class="tl-bar-fill" style="width:${pct}%;"></span></div>
          <div class="small">${r.count} events</div>
        </div>`;
    })
    .join("");

  setTimeout(() => {
    document.querySelectorAll("#historicalBaselineBars .tl-bar-fill").forEach((el) => el.classList.add("animated"));
  }, 180);
}

function renderAttackGlossary(events = []) {
  const el = document.getElementById("attackGlossary");
  if (!el) return;
  const counts = events.reduce((acc, e) => {
    const k = normalizeThreatKey(e.attackKind || e.type, e.source);
    acc[k] = (acc[k] || 0) + 1;
    acc.all = (acc.all || 0) + 1;
    return acc;
  }, {});
  const rows = [...attackGlossary].sort((a, b) => {
    const ca = Number(counts[a.key] || 0);
    const cb = Number(counts[b.key] || 0);
    if ((cb > 0) !== (ca > 0)) return cb > 0 ? 1 : -1;
    return cb - ca;
  });
  el.innerHTML = `<div class="glossary-grid quiet">${rows
    .map(
      (g) => {
        const observed = Number(counts[g.key] || 0);
        return `
      <article class="glossary-item quiet ${activeThreatKey === g.key ? "active" : ""} ${observed === 0 ? "zero" : ""}" data-threat-key="${g.key}">
        <div class="glossary-head">
          <h3 class="glossary-title">
            <span class="glossary-icon" style="--icon-url:url('${THREAT_ICONS[g.key] || THREAT_ICONS.unknown}');--icon-color:${THREAT_COLORS[g.key] || THREAT_COLORS.unknown};" aria-hidden="true"></span>
            ${g.type}
          </h3>
          <div class="glossary-right">
            <span class="glossary-count" style="border-color:color-mix(in srgb, ${THREAT_COLORS[g.key] || THREAT_COLORS.unknown} 40%, #2d4560);color:${THREAT_COLORS[g.key] || THREAT_COLORS.unknown};">${observed}</span>
            <button type="button" class="glossary-toggle" aria-expanded="${expandedThreatKey === g.key ? "true" : "false"}">${expandedThreatKey === g.key ? "−" : "+"}</button>
          </div>
        </div>
        <div class="glossary-body ${expandedThreatKey === g.key ? "expanded" : ""}">
          <p>${g.meaning}</p>
          <div class="small">Sources: ${(THREAT_SOURCE_MAP[g.key] || []).join(", ") || "Mapped from live alerts"}</div>
        </div>
      </article>`;
      }
    )
    .join("")}</div>`;

  el.querySelectorAll(".glossary-item").forEach((card) => {
    const key = card.getAttribute("data-threat-key") || "unknown";
    card.style.setProperty("--active-color", THREAT_COLORS[key] || THREAT_COLORS.unknown);
    const toggle = card.querySelector(".glossary-toggle");
    card.addEventListener("click", () => {
      activeThreatKey = card.getAttribute("data-threat-key") || "all";
      redrawMapByThreat();
      renderAttackGlossary(getGlossaryEvents());
      renderObservationSummary();
      renderGlossaryDetail();
    });
    toggle?.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const cardKey = card.getAttribute("data-threat-key") || "all";
      expandedThreatKey = expandedThreatKey === cardKey ? null : cardKey;
      renderAttackGlossary(getGlossaryEvents());
    });
  });
}

async function init() {
  renderThreatLog();
  const intelRes = await fetch("./data/netscout_2h2025_summary.json");
  const intel = await intelRes.json();
  const reportInsightsRes = await fetch("./data/report-insights.json");
  const reportInsights = await reportInsightsRes.json();
  const histRes = await fetch("./data/historical-threats.json");
  historicalEvents = await histRes.json();
  renderInsights(reportInsights, intel, historicalEvents);
  let refreshInFlight = false;
  let consecutiveFailures = 0;
  let lastGood = null;
  let seenLive = false;
  const FAILURE_GRACE = 3;
  const REFRESH_MS = 20000;
  const INITIAL_SLA_MS = 3000;
  const snapshotEndpoints = uniqueStrings(SNAPSHOT_ENDPOINTS);

  const fetchJsonWithTimeout = async (url, timeoutMs = 5000) => {
    const c = new AbortController();
    const id = setTimeout(() => c.abort(), timeoutMs);
    try {
      const res = await fetch(url, { signal: c.signal });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    } finally {
      clearTimeout(id);
    }
  };

  const fetchFirstJson = async (endpoints, timeoutMs = 5000) => {
    for (const endpoint of endpoints) {
      const data = await fetchJsonWithTimeout(endpoint, timeoutMs);
      if (data) return data;
    }
    return null;
  };

  const applyLiveData = (events, mapEvents, sourceHealth, mode = "live") => {
    liveAlertEvents = events || [];
    liveMapEvents = mapEvents || [];
    liveSourceHealth = sourceHealth || {};
    allMapEvents = getMapModeEvents();
    setLiveBadge(mode);
    redrawMapByThreat();
    renderAlerts(liveAlertEvents);
    renderFeedStatusPanel(liveSourceHealth);
    renderAttackGlossary(getGlossaryEvents());
    renderGlossaryDetail();
    renderObservationSummary();
    updateThreatLog(mapEvents || [], mode);
    renderThreatLog();
    updateHistoricalSourceNote();
    updateMapCount();
    if (mode === "live") {
      lastSyncedAt = new Date().toISOString();
      updateTopBadges();
    }
    if (events.length || mapEvents.length) {
      saveLiveCache(events, mapEvents, liveSourceHealth);
    }
  };

  const refreshLiveData = async (isInitial = false) => {
    if (refreshInFlight) return;
    refreshInFlight = true;
    if (!seenLive) setLiveLoading(true, "Syncing live feeds...");
    try {
      const timeoutMs = isInitial ? INITIAL_SLA_MS : 5000;
      const live = await fetchFirstJson(snapshotEndpoints, timeoutMs);
      if (!live) throw new Error("live unavailable");

      const events = live.events || [];
      let mapEvents = live.map_events || [];
      if (!mapEvents.length) {
        const fallback = buildExpandedFallbackEvents(120);
        if (fallback.length) mapEvents = fallback;
      }
      lastGood = { events, mapEvents, sourceHealth: live.source_health || {} };
      consecutiveFailures = 0;
      seenLive = true;
      applyLiveData(events, mapEvents, lastGood.sourceHealth, "live");
      setLiveLoading(false);
    } catch {
      consecutiveFailures += 1;
      if (lastGood && consecutiveFailures < FAILURE_GRACE) {
        applyLiveData(lastGood.events, lastGood.mapEvents, lastGood.sourceHealth, "degraded");
        if (!seenLive) setLiveLoading(true, "Syncing live feeds...");
      } else {
        const fallback = buildExpandedFallbackEvents(120);
        const mode = "degraded";
        applyLiveData(fallback, fallback, lastGood?.sourceHealth || {}, mode);
        if (!seenLive) setLiveLoading(true, "Syncing live feeds...");
      }
    } finally {
      refreshInFlight = false;
    }
  };

  const cached = safeLoadLiveCache();
  if (cached && (cached.events.length || cached.mapEvents.length)) {
    lastSyncedAt = cached.updatedAt || lastSyncedAt;
    updateTopBadges();
    const mapEvents = cached.mapEvents.length ? cached.mapEvents : cached.events;
    applyLiveData(cached.events, mapEvents, cached.sourceHealth || {}, "degraded");
    setLiveLoading(true, "Syncing live feeds...");
  } else {
    const initialFallback = buildExpandedFallbackEvents(120);
    if (initialFallback.length) {
      applyLiveData(initialFallback, initialFallback, {}, "degraded");
      setLiveLoading(true, "Syncing live feeds...");
    }
  }

  await refreshLiveData(true);
  if (!seenLive) {
    setLiveLoading(true, "Syncing live feeds...");
  }
  window.setInterval(updateTopBadges, 1000);
  renderSources();
  const sourcesToggle = document.getElementById("sourcesToggle");
  const sourcesWrap = document.getElementById("sourcesWrap");
  if (sourcesToggle && sourcesWrap) {
    const syncSourcesToggle = () => {
      const collapsed = sourcesWrap.classList.contains("collapsed");
      sourcesToggle.textContent = collapsed ? "Show" : "Hide";
      sourcesToggle.setAttribute("aria-expanded", collapsed ? "false" : "true");
    };
    syncSourcesToggle();
    sourcesToggle.addEventListener("click", () => {
      sourcesWrap.classList.toggle("collapsed");
      syncSourcesToggle();
    });
  }
  const feedStatusToggle = document.getElementById("feedStatusToggle");
  const feedStatusWrap = document.getElementById("feedStatusWrap");
  if (feedStatusToggle && feedStatusWrap) {
    const syncFeedStatusToggle = () => {
      const collapsed = feedStatusWrap.classList.contains("collapsed");
      feedStatusToggle.setAttribute("aria-expanded", collapsed ? "false" : "true");
    };
    syncFeedStatusToggle();
    feedStatusToggle.addEventListener("click", () => {
      feedStatusWrap.classList.toggle("collapsed");
      syncFeedStatusToggle();
    });
  }
  const threatLogToggle = document.getElementById("threatLogToggle");
  const threatLogWrap = document.getElementById("threatLogWrap");
  if (threatLogToggle && threatLogWrap) {
    const syncThreatLogToggle = () => {
      const collapsed = threatLogWrap.classList.contains("collapsed");
      threatLogToggle.setAttribute("aria-expanded", collapsed ? "false" : "true");
    };
    syncThreatLogToggle();
    threatLogToggle.addEventListener("click", () => {
      threatLogWrap.classList.toggle("collapsed");
      syncThreatLogToggle();
    });
  }
  window.setInterval(() => {
    refreshLiveData(false);
  }, REFRESH_MS);
}

threatLog = safeLoadThreatLog();
init();
