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

    min_count = env_int("MIN_SNAPSHOT_EVENT_COUNT", 120)
    min_map_count = env_int("MIN_SNAPSHOT_MAP_COUNT", 60)
    min_non_context_ok = env_int("MIN_SNAPSHOT_NON_CONTEXT_OK", 3)
    allow_context_only = os.getenv("ALLOW_CONTEXT_ONLY_SNAPSHOT", "").strip().lower() in {"1", "true", "yes", "on"}

    if allow_context_only:
        return True, "context-only override enabled"
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
    if not healthy:
        print(f"Snapshot rejected: {reason}", file=sys.stderr)
        sys.exit(3)
    payload["snapshot_generated_at"] = datetime.now(timezone.utc).isoformat()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote snapshot: {OUT_PATH} ({payload.get('count', 0)} events)")


if __name__ == "__main__":
    asyncio.run(main())
