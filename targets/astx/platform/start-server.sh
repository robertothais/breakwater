#!/bin/bash
set -e

mkdir -p /var/log/astx /tmp/astx

echo "Starting WebVM ASTx daemon..."
nohup /usr/local/bin/run-astx >/var/log/astx/daemon.log 2>&1 &
DAEMON_PID=$!

sleep 5

echo "Starting WebVM request handler..."
nohup /usr/local/bin/request-handler >/var/log/astx/handler.log 2>&1 &
HANDLER_PID=$!

sleep 2

echo "$DAEMON_PID" >/tmp/astx/daemon.pid
echo "$HANDLER_PID" >/tmp/astx/handler.pid

echo "WebVM ASTx server started"
echo "Daemon PID: $DAEMON_PID"
echo "Handler PID: $HANDLER_PID"
