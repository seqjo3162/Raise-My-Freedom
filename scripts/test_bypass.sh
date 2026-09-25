#!/bin/bash
URL="${1:-https://discord.com/api/download?platform=linux&format=deb}"
OUT="/tmp/test_download"
echo "=== rmf bypass speed test ==="
echo "URL: $URL"
echo "Start: $(date)"
echo ""

# Качаем с прогрессом и скоростью
curl -L -o "$OUT" --max-time 120 --retry 2 \
  --connect-timeout 10 \
  -w "\n\n--- Stats ---\nTotal: %{size_download} bytes\nSpeed: %{speed_download} B/s\nTime: %{time_total}s\nHTTP: %{http_code}\n" \
  "$URL" 2>&1

RC=$?
FSIZE=$(stat -c%s "$OUT" 2>/dev/null || echo 0)
echo ""
echo "File size: $FSIZE bytes"
echo "Exit code: $RC"
echo "End: $(date)"

if [ "$FSIZE" -gt 1000000 ] && [ "$RC" -eq 0 ]; then
    echo "RESULT: OK"
else
    echo "RESULT: FAIL"
fi
rm -f "$OUT"
