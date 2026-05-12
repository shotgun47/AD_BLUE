#!/usr/bin/env bash
set -eu

RUN_ID="${1:-run-manual}"
PARAMS_JSON="${2:-}"

if [ -z "$PARAMS_JSON" ]; then
  PARAMS_JSON='{}'
fi

PYTHON_BIN="/home/ubuntu/attack-runner/venv/bin/python3"

get_param() {
  local key="$1"
  local default_value="${2:-}"
  "$PYTHON_BIN" - "$PARAMS_JSON" "$key" "$default_value" <<'PY'
import json
import sys
raw = sys.argv[1]
key = sys.argv[2]
default_value = sys.argv[3]
try:
    data = json.loads(raw)
    value = data.get(key, default_value)
    print(value if value is not None else "")
except Exception:
    print(default_value)
PY
}

# ===== 파라미터 추출 =====
TARGET_IP="$(get_param target_ip 100.110.203.60)"
WINRM_USER="$(get_param winrm_user lab_admin)"
WINRM_PASS="$(get_param winrm_pass)"
DOMAIN_NAME="$(get_param domain_name lab.local)"

# ===== 결과물 저장 경로 =====
RESULT_DIR="/home/ubuntu/attack-runner/data/pingcastle/${RUN_ID}"
mkdir -p "$RESULT_DIR"

# ===== 필수 파라미터 검증 =====
if [ -z "$WINRM_PASS" ]; then
  echo "[ERROR] winrm_pass is required"
  exit 1
fi

if ! command -v evil-winrm >/dev/null 2>&1; then
  echo "[ERROR] evil-winrm is not installed"
  exit 1
fi

REPORT_HTML="ad_hc_${DOMAIN_NAME}.html"
REPORT_XML="ad_hc_${DOMAIN_NAME}.xml"

echo "[INFO] =========================================="
echo "[INFO] PingCastle HealthCheck started"
echo "[INFO] run_id      : $RUN_ID"
echo "[INFO] target_ip   : $TARGET_IP"
echo "[INFO] winrm_user  : $WINRM_USER"
echo "[INFO] domain_name : $DOMAIN_NAME"
echo "[INFO] report_html : $REPORT_HTML"
echo "[INFO] result_dir  : $RESULT_DIR"
echo "[INFO] =========================================="

# ===== DC에서 PingCastle 실행 명령 =====
# 핵심: --user / --password 로 LDAP 인증 명시 전달 (double-hop 우회)
TMP_CMDS="/tmp/pingcastle_cmd_${RUN_ID}.txt"

cat > "$TMP_CMDS" <<EOF
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
cd C:\\Tools\\PingCastle
Remove-Item -Force -ErrorAction SilentlyContinue ${REPORT_HTML}
Remove-Item -Force -ErrorAction SilentlyContinue ${REPORT_XML}
.\\PingCastle.exe --healthcheck --server ${DOMAIN_NAME} --user "${WINRM_USER}" --password "${WINRM_PASS}"
Write-Host "===PINGCASTLE_DONE==="
if (Test-Path ${REPORT_HTML}) { Write-Host "===REPORT_HTML_OK===" } else { Write-Host "===REPORT_HTML_MISSING===" }
if (Test-Path ${REPORT_XML})  { Write-Host "===REPORT_XML_OK==="  } else { Write-Host "===REPORT_XML_MISSING===" }
download ${REPORT_HTML} ${REPORT_HTML}
download ${REPORT_XML} ${REPORT_XML}
exit
EOF

echo "[INFO] Executing PingCastle on target via evil-winrm..."

set +e
cd "$RESULT_DIR"
evil-winrm -i "$TARGET_IP" -u "$WINRM_USER" -p "$WINRM_PASS" < "$TMP_CMDS"
WINRM_RC=$?
set -e

rm -f "$TMP_CMDS"

# ===== 결과 검증 =====
echo "[INFO] =========================================="
HTML_OK=0
XML_OK=0

if [ -f "${RESULT_DIR}/${REPORT_HTML}" ]; then
  HTML_SIZE=$(stat -c%s "${RESULT_DIR}/${REPORT_HTML}" 2>/dev/null || echo "0")
  if [ "$HTML_SIZE" -gt 1000 ]; then
    echo "[INFO] HTML report : ${RESULT_DIR}/${REPORT_HTML} (${HTML_SIZE} bytes) OK"
    HTML_OK=1
  else
    echo "[WARN] HTML report too small (${HTML_SIZE} bytes), likely incomplete"
  fi
else
  echo "[ERROR] HTML report not found"
fi

if [ -f "${RESULT_DIR}/${REPORT_XML}" ]; then
  XML_SIZE=$(stat -c%s "${RESULT_DIR}/${REPORT_XML}" 2>/dev/null || echo "0")
  if [ "$XML_SIZE" -gt 100 ]; then
    echo "[INFO] XML report  : ${RESULT_DIR}/${REPORT_XML} (${XML_SIZE} bytes) OK"
    XML_OK=1
  else
    echo "[WARN] XML report too small (${XML_SIZE} bytes), likely incomplete"
  fi
else
  echo "[ERROR] XML report not found"
fi

# ===== 최종 종료 코드 결정 =====
# evil-winrm 자체가 실패했거나, 보고서가 둘 다 없으면 실패
if [ "$WINRM_RC" -ne 0 ]; then
  echo "[ERROR] evil-winrm exited with code $WINRM_RC"
  FINAL_RC=$WINRM_RC
elif [ "$HTML_OK" -eq 0 ] && [ "$XML_OK" -eq 0 ]; then
  echo "[ERROR] Neither HTML nor XML report was generated. PingCastle likely failed."
  FINAL_RC=2
else
  echo "[INFO] Reports generated successfully"
  FINAL_RC=0
fi

echo "[INFO] PingCastle HealthCheck finished"
echo "[INFO] return code : $FINAL_RC"
echo "[INFO] =========================================="

exit "$FINAL_RC"