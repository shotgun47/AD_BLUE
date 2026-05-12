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

echo "[INFO] Scenario: Remove Group Member started by $REQUESTED_BY"
echo "[INFO] Target DC: $TARGET_IP"
echo "[INFO] Remove $USER_NAME from $GROUP_NAME"

set +e
net rpc group delmem "$GROUP_NAME" "$USER_NAME" -I "$TARGET_IP" -U "administrator%admin123!"
RC=$?
set -e

if [ $RC -eq 0 ]; then
    echo "[SUCCESS] User $USER_NAME removed from $GROUP_NAME successfully."
else
    echo "[FAILURE] Failed to remove user. User might not be in the group or network issue."
fi