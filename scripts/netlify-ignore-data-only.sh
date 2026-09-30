#!/usr/bin/env bash

# Netlify cancels a build when this command exits successfully. Snapshot-only
# commits do not need a new production deployment because the browser reads the
# current snapshot directly from GitHub.
if [[ -z "${CACHED_COMMIT_REF:-}" || -z "${COMMIT_REF:-}" ]]; then
  exit 1
fi

git diff --quiet "$CACHED_COMMIT_REF" "$COMMIT_REF" -- . ':(exclude)data/live-threats.json'
