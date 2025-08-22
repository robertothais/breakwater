#!/bin/bash
set -e

REQUEST_FILE="/tmp/astx/request"
RESPONSE_FILE="/tmp/astx/response"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <endpoint> [params]"
  exit 1
fi

ENDPOINT="$1"
PARAMS="${2:-}"

echo "Sending WebVM request: endpoint='$ENDPOINT' params='$PARAMS'"
echo "$ENDPOINT $PARAMS" >"$REQUEST_FILE"

echo "Waiting for response..."
timeout_count=0
while [ $timeout_count -lt 100 ]; do
  if [ -f "$RESPONSE_FILE" ]; then
    cat "$RESPONSE_FILE"
    rm -f "$RESPONSE_FILE"
    echo ""
    echo "Request completed successfully"
    exit 0
  fi
  sleep 0.1
  timeout_count=$((timeout_count + 1))
done

echo "ERROR: Request timed out or failed"
exit 1
