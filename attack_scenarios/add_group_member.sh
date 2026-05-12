#!/usr/bin/env bash
set -eu

RUN_ID="${1:-run-manual}"
PARAMS_JSON="${2:-}"
if [ -z "$PARAMS_JSON" ]; then
  PARAMS_JSON='{}'
fi

echo "[DEBUG] RUN_ID=$RUN_ID"
echo "[DEBUG] PARAMS_JSON_RAW=$PARAMS_JSON"

get_param() {
  local key="$1"
  local default_value="${2:-}"
  python3 - "$PARAMS_JSON" "$key" "$default_value" <<'PY'
import json
import sys

raw = sys.argv[1]
key = sys.argv[2]
default_value = sys.argv[3]

try:
    data = json.loads(raw)
    value = data.get(key, default_value)
    if value is None:
        print("")
    else:
        print(value)
except:
    print(default_value)
PY
}

TARGET_IP="$(get_param target_ip "")"
REQUESTED_BY="$(get_param requested_by "Unknown")"
GROUP_NAME="$(get_param group_name "Test Group")"
USER_NAME="$(get_param user_name "victim")"

if [ -z "$TARGET_IP" ]; then
  echo "[ERROR] target_ip is required"
  exit 1
fi

if [ -z "$USER_NAME" ]; then
  echo "[ERROR] user_name is required"
  exit 1
fi

echo "[INFO] Scenario: Add Group Member started by $REQUESTED_BY"
echo "[INFO] Target Domain Controller: $TARGET_IP"
echo "[INFO] Target Group: $GROUP_NAME"
echo "[INFO] Target User: $USER_NAME"

set +e
net rpc group addmem "$GROUP_NAME" "$USER_NAME" -I "$TARGET_IP" -U "administrator%admin123!"
RC=$?
set -e

if [ $RC -eq 0 ]; then
    echo "[SUCCESS] User $USER_NAME added to $GROUP_NAME successfully."
else
    echo "[FAILURE] Failed to add user to group. Check credentials or network status."
fi