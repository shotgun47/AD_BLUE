#!/usr/bin/env bash
set -euo pipefail

RUN_ID="${1:-}"
PARAMS_JSON="${2:-}"

if [[ -z "$RUN_ID" ]]; then
  echo "[!] run_id(1번 인자)가 비어 있습니다."
  exit 1
fi

if [[ -z "$PARAMS_JSON" ]]; then
  echo "[!] params_json(2번 인자)가 비어 있습니다."
  exit 1
fi


PYTHON_BIN="/home/ubuntu/attack-runner/venv/bin/python"

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "[!] python 실행 파일을 찾을 수 없습니다: $PYTHON_BIN"
  exit 1
fi

readarray -t PARSED < <("$PYTHON_BIN" - <<'PY' "$PARAMS_JSON"
import json, sys

raw = sys.argv[1]
data = json.loads(raw)

print(data.get("target_ip", ""))
print(data.get("requested_by", ""))
print(data.get("domain", ""))
print(data.get("username", ""))
print(data.get("password", ""))
PY
)

TARGET_IP="${PARSED[0]:-}"
REQUESTED_BY="${PARSED[1]:-unknown}"
DOMAIN="${PARSED[2]:-}"
USERNAME="${PARSED[3]:-}"
PASSWORD="${PARSED[4]:-}"

if [[ -z "$TARGET_IP" ]]; then
  echo "[!] target_ip 가 비어 있습니다."
  exit 1
fi
if [[ -z "$DOMAIN" ]]; then
  echo "[!] domain 이 비어 있습니다."
  exit 1
fi
if [[ -z "$USERNAME" ]]; then
  echo "[!] username 이 비어 있습니다."
  exit 1
fi
if [[ -z "$PASSWORD" ]]; then
  echo "[!] password 가 비어 있습니다."
  exit 1
fi


WMIEXEC_BIN="/home/ubuntu/attack-runner/venv/bin/wmiexec.py"

if [[ ! -x "$WMIEXEC_BIN" ]]; then
  echo "[!] wmiexec.py 실행 파일을 찾을 수 없습니다: $WMIEXEC_BIN"
  exit 1
fi


echo "[*] run_id=${RUN_ID}"
echo "[*] requested_by=${REQUESTED_BY}"
echo "[*] target_ip=${TARGET_IP}"
echo "[*] auth=${DOMAIN}\\${USERNAME}"
echo "[*] using=${WMIEXEC_BIN}"


REMOTE_CMD='cmd.exe /Q /c for /L %i in (1,1,5) do powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output ''PowerShell rule test started''; Start-Sleep -Seconds 1"'



set +e
"$WMIEXEC_BIN" "${DOMAIN}/${USERNAME}:${PASSWORD}@${TARGET_IP}" "$REMOTE_CMD"
RC=$?
set -e

echo "[*] wmiexec return_code=${RC}"
if [[ ${RC} -ne 0 ]]; then
  echo "[!] 원격 PowerShell 실행 실패"
  exit ${RC}
fi

echo "[+] 원격 PowerShell 실행 완료"
echo "[*] 기대 확인 포인트:"
echo "    - event_id=4688"
echo "    - detection_json.rule_id 가 RULE-041 또는 RULE-042 인지"
echo "    - event_json.service_name 값이 powershell.exe 로 들어오는지"