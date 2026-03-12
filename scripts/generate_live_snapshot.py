#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.main import live_threats  # noqa: E402


OUT_PATH = ROOT / "data" / "live-threats.json"


async def main() -> None:
    payload = await live_threats(force_refresh=True)
    payload["snapshot_generated_at"] = datetime.now(timezone.utc).isoformat()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote snapshot: {OUT_PATH} ({payload.get('count', 0)} events)")


if __name__ == "__main__":
    asyncio.run(main())
