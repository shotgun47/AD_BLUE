#!/bin/bash
set -u

RUN_ID="$1"
PARAMS_JSON="$2"

TARGET_IP=$(echo "$PARAMS_JSON" | jq -r '.target_ip // empty')

echo "[INFO] test_ping started"
echo "[INFO] run_id=$RUN_ID"
echo "[INFO] params=$PARAMS_JSON"
echo "[INFO] target_ip=$TARGET_IP"

if [ -z "$TARGET_IP" ]; then
  echo "[ERROR] target_ip is missing"
  exit 1
fi

echo "[INFO] pinging $TARGET_IP"
ping -c 4 "$TARGET_IP"
PING_RC=$?

if [ $PING_RC -eq 0 ]; then
  echo "[INFO] ping success"
  exit 0
else
  echo "[ERROR] ping failed"
  exit 1
fi