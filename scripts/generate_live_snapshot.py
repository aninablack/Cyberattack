#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.main import live_threats  # noqa: E402


OUT_PATH = ROOT / "data" / "live-threats.json"
LAST_GOOD_PATH = ROOT / "data" / "live-threats.last-good.json"


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def snapshot_is_healthy(payload: dict) -> tuple[bool, str]:
    count = int(payload.get("count") or 0)
    map_count = int(payload.get("map_count") or 0)
    events = payload.get("events") if isinstance(payload.get("events"), list) else []
    map_events = payload.get("map_events") if isinstance(payload.get("map_events"), list) else []
    source_health = payload.get("source_health") if isinstance(payload.get("source_health"), dict) else {}
    sources = payload.get("sources") if isinstance(payload.get("sources"), dict) else {}

    # Healthy snapshots should include at least one non-context feed with data.
    non_context_ok = 0
    if source_health:
        for name, entry in source_health.items():
            if str(name).lower() == "context" or not isinstance(entry, dict):
                continue
            status = str(entry.get("status") or "")
            reason = str(entry.get("reason") or "")
            if status.startswith("ok:") and reason == "ok":
                try:
                    if int(status.split(":", 1)[1]) > 0:
                        non_context_ok += 1
                except Exception:
                    pass
    elif sources:
        for name, raw in sources.items():
            if str(name).lower() == "context":
                continue
            status = str(raw or "")
            if status.startswith("ok:"):
                try:
                    if int(status.split(":", 1)[1]) > 0:
                        non_context_ok += 1
                except Exception:
                    pass

    # Conservative defaults: block obvious context-only/empty snapshots,
    # but avoid failing healthy-yet-lean refreshes.
    min_count = env_int("MIN_SNAPSHOT_EVENT_COUNT", 60)
    min_map_count = env_int("MIN_SNAPSHOT_MAP_COUNT", 20)
    min_non_context_ok = env_int("MIN_SNAPSHOT_NON_CONTEXT_OK", 1)
    min_non_context_events = env_int("MIN_SNAPSHOT_NON_CONTEXT_EVENTS", 30)
    min_non_context_map_events = env_int("MIN_SNAPSHOT_NON_CONTEXT_MAP_EVENTS", 12)
    allow_context_only = os.getenv("ALLOW_CONTEXT_ONLY_SNAPSHOT", "").strip().lower() in {"1", "true", "yes", "on"}

    non_context_events = [
        e
        for e in events
        if isinstance(e, dict) and str(e.get("source") or "").strip().lower() != "historical-context"
    ]
    non_context_map_events = [
        e
        for e in map_events
        if isinstance(e, dict) and str(e.get("source") or "").strip().lower() != "historical-context"
    ]

    if allow_context_only:
        return True, "context-only override enabled"
    if len(non_context_events) < min_non_context_events:
        return False, f"non-context events too low ({len(non_context_events)} < {min_non_context_events})"
    if len(non_context_map_events) < min_non_context_map_events:
        return False, f"non-context map events too low ({len(non_context_map_events)} < {min_non_context_map_events})"
    if non_context_ok < min_non_context_ok:
        return False, f"non-context healthy feeds too low ({non_context_ok} < {min_non_context_ok})"
    if count < min_count:
        return False, f"event count too low ({count} < {min_count})"
    if map_count < min_map_count:
        return False, f"map count too low ({map_count} < {min_map_count})"
    return True, "ok"


async def main() -> None:
    payload = await live_threats(force_refresh=True)
    healthy, reason = snapshot_is_healthy(payload)
    now_iso = datetime.now(timezone.utc).isoformat()
    if not healthy:
        # On CI runners, local last-good may not exist. Keep workflow green and let publish step skip updates.
        if LAST_GOOD_PATH.exists():
            try:
                backup = json.loads(LAST_GOOD_PATH.read_text(encoding="utf-8"))
                if isinstance(backup, dict):
                    backup["snapshot_generated_at"] = now_iso
                    backup["snapshot_mode"] = "last_good_fallback"
                    backup["snapshot_fallback_reason"] = reason
                    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
                    OUT_PATH.write_text(json.dumps(backup, ensure_ascii=False), encoding="utf-8")
                    print(f"Live snapshot unhealthy ({reason}); reused last good snapshot: {LAST_GOOD_PATH}")
                    print(f"Wrote snapshot: {OUT_PATH} ({backup.get('count', 0)} events)")
                    return
            except Exception:
                pass
        payload["snapshot_generated_at"] = now_iso
        payload["snapshot_mode"] = "degraded_local"
        payload["snapshot_fallback_reason"] = reason
        OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        OUT_PATH.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        print(f"Live snapshot unhealthy ({reason}); wrote degraded snapshot for publish guard.")
        print(f"Wrote snapshot: {OUT_PATH} ({payload.get('count', 0)} events)")
        return
    payload["snapshot_generated_at"] = now_iso
    payload["snapshot_mode"] = "live"
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    LAST_GOOD_PATH.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote snapshot: {OUT_PATH} ({payload.get('count', 0)} events)")


if __name__ == "__main__":
    asyncio.run(main())
