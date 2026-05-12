#!/usr/bin/env bash
set -eu

RUN_ID="${1:-run-manual}"
PARAMS_JSON="${2:-}"
if [ -z "$PARAMS_JSON" ]; then
  PARAMS_JSON='{}'
fi


get_param() {
  local key="$1"
  local default_value="${2:-}"
  python3 - "$PARAMS_JSON" "$key" "$default_value" <<'PY'
import json
import sys

raw = sys.argv[1]
key = sys.argv[2]
default_value = sys.argv[3]

data = json.loads(raw)
value = data.get(key, default_value)

if value is None:
    print("")
else:
    print(value)
PY
}

TARGET_IP="$(get_param target_ip "")"
REQUESTED_BY="$(get_param requested_by "")"
USERNAME="$(get_param username "")"
PASSWORD="$(get_param password "")"
DOMAIN="$(get_param domain "")"
ATTEMPTS="$(get_param attempts "1")"
SLEEP_SEC="$(get_param sleep_sec "1")"


if [ -z "$TARGET_IP" ]; then
  echo "[ERROR] target_ip is required"
  exit 1
fi

if [ -z "$USERNAME" ]; then
  echo "[ERROR] username is required"
  exit 1
fi

if [ -z "$PASSWORD" ]; then
  echo "[ERROR] password is required"
  exit 1
fi

if ! command -v smbclient >/dev/null 2>&1; then
  echo "[ERROR] smbclient is not installed"
  echo "[HINT] Ubuntu/Debian: sudo apt-get update && sudo apt-get install -y smbclient"
  exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
  echo "[ERROR] timeout command is not available"
  exit 1
fi

if ! [[ "$ATTEMPTS" =~ ^[0-9]+$ ]] || [ "$ATTEMPTS" -lt 1 ]; then
  echo "[ERROR] attempts must be a positive integer"
  exit 1
fi

if ! [[ "$SLEEP_SEC" =~ ^[0-9]+$ ]]; then
  echo "[ERROR] sleep_sec must be an integer"
  exit 1
fi

echo "[INFO] run_id=$RUN_ID"
echo "[INFO] requested_by=${REQUESTED_BY:-unknown}"
echo "[INFO] target_ip=$TARGET_IP"
echo "[INFO] username=$USERNAME"
echo "[INFO] domain=${DOMAIN:-WORKGROUP}"
echo "[INFO] attempts=$ATTEMPTS"

# Windows IPC$에 잘못된 자격증명으로 SMB 인증 시도
# 목적: victim Security 로그에 4625 실패 로그인 이벤트 생성
for i in $(seq 1 "$ATTEMPTS"); do
  echo "[INFO] attempt $i/$ATTEMPTS"

  if [ -n "$DOMAIN" ]; then
    AUTH_USER="${DOMAIN}\\${USERNAME}"
  else
    AUTH_USER="$USERNAME"
  fi

  set +e
  timeout 8 smbclient "//${TARGET_IP}/IPC$" \
    -U "${AUTH_USER}%${PASSWORD}" \
    -m SMB3 \
    -c 'quit' >/tmp/"${RUN_ID}"_attempt_"${i}".log 2>&1
  RC=$?
  set -e

  echo "[INFO] smbclient return_code=$RC"

  if [ -f /tmp/"${RUN_ID}"_attempt_"${i}".log ]; then
    tail -n 5 /tmp/"${RUN_ID}"_attempt_"${i}".log || true
  fi

  if [ "$i" -lt "$ATTEMPTS" ]; then
    sleep "$SLEEP_SEC"
  fi
done

echo "[INFO] scenario finished"
echo "[INFO] expected on victim: Security Event ID 4625"
echo "[INFO] possible additional events: 4776 or related auth failure logs"