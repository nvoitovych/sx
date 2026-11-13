#!/usr/bin/env bash
# Polls until Apple finishes notarizing the uploaded archive, then exports the stapled app.
set -euo pipefail
ARCHIVE="$1"; OUT="$2"
for i in $(seq 1 60); do
  if xcodebuild -exportNotarizedApp -archivePath "$ARCHIVE" -exportPath "$OUT" >/tmp/sx-notary.log 2>&1; then
    echo "notarized → $OUT"; exit 0
  fi
  grep -qiE 'invalid|rejected' /tmp/sx-notary.log && { cat /tmp/sx-notary.log; exit 1; }
  sleep 30
done
echo "timed out waiting for notarization"; exit 1
