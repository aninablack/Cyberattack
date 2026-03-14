#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_PATH = ROOT / "data" / "live-threats.json"


def required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        print(f"Missing required env var: {name}", file=sys.stderr)
        sys.exit(2)
    return value


def main() -> None:
    gist_id = required_env("GIST_ID")
    gist_token = required_env("GIST_TOKEN")
    gist_filename = os.getenv("GIST_FILENAME", "live-threats.json").strip() or "live-threats.json"

    if not SNAPSHOT_PATH.exists():
        print(f"Snapshot file not found: {SNAPSHOT_PATH}", file=sys.stderr)
        sys.exit(2)

    content = SNAPSHOT_PATH.read_text(encoding="utf-8")
    try:
        snapshot = json.loads(content)
    except Exception as exc:
        print(f"Snapshot JSON parse failed: {exc}", file=sys.stderr)
        sys.exit(2)

    mode = str(snapshot.get("snapshot_mode") or "").strip().lower()
    count = int(snapshot.get("count") or 0)
    map_count = int(snapshot.get("map_count") or 0)
    reason = str(snapshot.get("snapshot_fallback_reason") or "").strip()
    if mode.startswith("degraded"):
        print(
            f"Skipping gist publish: degraded snapshot mode='{mode}' reason='{reason}' count={count} map_count={map_count}"
        )
        return
    payload = {
        "description": "Cyber threat dashboard live snapshot (auto-updated)",
        "files": {gist_filename: {"content": content}},
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=f"https://api.github.com/gists/{gist_id}",
        data=body,
        method="PATCH",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {gist_token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        print(f"Gist update failed: HTTP {exc.code} {detail}", file=sys.stderr)
        sys.exit(1)

    files = resp_data.get("files") or {}
    raw_url = (files.get(gist_filename) or {}).get("raw_url")
    print(f"Updated gist {gist_id} file={gist_filename}")
    if raw_url:
        print(f"Raw URL: {raw_url}")


if __name__ == "__main__":
    main()
