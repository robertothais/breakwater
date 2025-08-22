#!/bin/bash
set -e

REQUEST_FILE="/tmp/astx/request"
RESPONSE_FILE="/tmp/astx/response"
LOCK_FILE="/tmp/astx/lock"

echo "Starting WebVM request handler for real ASTx daemon"
rm -f "$REQUEST_FILE" "$RESPONSE_FILE" "$LOCK_FILE"

echo "Waiting for ASTx daemon to be ready..."
sleep 5

while true; do
  if [ -f "$REQUEST_FILE" ] && [ ! -f "$LOCK_FILE" ]; then
    touch "$LOCK_FILE"

    if [ -s "$REQUEST_FILE" ]; then
      read -r endpoint params <"$REQUEST_FILE"
      echo "Processing request: $endpoint $params"

      # Make HTTPS request to real ASTx daemon (port 55920)
      url="https://localhost:55920$endpoint"
      if [ -n "$params" ]; then
        url="$url?$params"
      fi

      echo "Making request to ASTx daemon: $url"

      # Try curl with verbose output
      echo "Attempting curl request..."
      response=$(curl -k -v -m 10 "$url" 2>&1)
      curl_exit=$?

      echo "Curl exit code: $curl_exit"
      echo "Curl output: $response"

      if [ $curl_exit -eq 0 ]; then
        # Extract actual response (last line usually)
        actual_response=$(echo "$response" | tail -1)
        echo "Got ASTx response: $actual_response"
        echo "$actual_response" >"$RESPONSE_FILE"
      else

        echo "ASTx daemon request failed with exit code: $curl_exit"
        echo "Full curl error: $response"
        echo "ERROR: ASTx daemon request failed" >"$RESPONSE_FILE"
      fi

      rm -f "$REQUEST_FILE"
    fi

    rm -f "$LOCK_FILE"
  fi
  sleep 0.1
done
