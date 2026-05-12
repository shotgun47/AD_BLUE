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
BACKEND_URL="$(get_param backend_url "${BACKEND_URL:-}")"

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



# ===== backend recon-results 업로드 =====
if [ "$FINAL_RC" -eq 0 ] && [ -n "$BACKEND_URL" ]; then
  echo "[INFO] Uploading PingCastle result to backend: ${BACKEND_URL}"

  HTML_PATH="${RESULT_DIR}/${REPORT_HTML}"
  XML_PATH="${RESULT_DIR}/${REPORT_XML}"

  "$PYTHON_BIN" - "$BACKEND_URL" "$RUN_ID" "$DOMAIN_NAME" "$TARGET_IP" "$HTML_PATH" "$XML_PATH" <<'PY'
import base64
import json
import os
import sys
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter

backend_url = sys.argv[1].rstrip("/")
run_id = sys.argv[2]
domain = sys.argv[3]
target_ip = sys.argv[4]
html_path = sys.argv[5]
xml_path = sys.argv[6]


def make_artifact(path, mime_type):
    if not os.path.exists(path):
        return None

    with open(path, "rb") as f:
        content_base64 = base64.b64encode(f.read()).decode("ascii")

    return {
        "filename": os.path.basename(path),
        "mime_type": mime_type,
        "content_base64": content_base64,
    }


def parse_int(value, default=0):
    try:
        return int(str(value).strip())
    except Exception:
        return default


def text_of(root, tag, default=None):
    node = root.find(tag)
    if node is None or node.text is None:
        return default
    return node.text.strip()


def parse_pingcastle_xml(xml_path):
    if not os.path.exists(xml_path):
        return {}

    try:
        root = ET.parse(xml_path).getroot()
    except Exception as exc:
        return {
            "xml_parse_error": str(exc),
        }

    summary = {
        "engine_version": text_of(root, "EngineVersion"),
        "generation_date": text_of(root, "GenerationDate"),
        "domain_fqdn": text_of(root, "DomainFQDN"),
        "netbios_name": text_of(root, "NetBIOSName"),
        "forest_fqdn": text_of(root, "ForestFQDN"),
        "maturity_level": parse_int(text_of(root, "MaturityLevel")),
        "is_privileged_mode": text_of(root, "IsPrivilegedMode"),
        "number_of_dc": parse_int(text_of(root, "NumberOfDC")),
        "global_score": parse_int(text_of(root, "GlobalScore")),
        "stale_objects_score": parse_int(text_of(root, "StaleObjectsScore")),
        "privileged_group_score": parse_int(text_of(root, "PrivilegiedGroupScore")),
        "trust_score": parse_int(text_of(root, "TrustScore")),
        "anomaly_score": parse_int(text_of(root, "AnomalyScore")),
        "machine_account_quota": parse_int(text_of(root, "MachineAccountQuota")),
        "admin_sdholder_not_ok_count": parse_int(text_of(root, "AdminSDHolderNotOKCount")),
        "unix_password_users_count": parse_int(text_of(root, "UnixPasswordUsersCount")),
        "smart_card_not_ok_count": parse_int(text_of(root, "SmartCardNotOKCount")),
        "domain_controller_with_null_session_count": parse_int(text_of(root, "DomainControllerWithNullSessionCount")),
    }

    risk_rules = []
    category_counter = Counter()
    point_counter = Counter()

    risk_root = root.find("RiskRules")
    if risk_root is not None:
        for item in risk_root.findall("HealthcheckRiskRule"):
            risk = {
                "points": parse_int(text_of(item, "Points")),
                "category": text_of(item, "Category", ""),
                "model": text_of(item, "Model", ""),
                "risk_id": text_of(item, "RiskId", ""),
                "rationale": text_of(item, "Rationale", ""),
            }

            risk_rules.append(risk)

            if risk["category"]:
                category_counter[risk["category"]] += 1

            point_counter[str(risk["points"])] += 1

    positive_rules = [r for r in risk_rules if r["points"] > 0]
    high_point_rules = [r for r in risk_rules if r["points"] >= 10]

    summary.update({
        "risk_rule_total": len(risk_rules),
        "risk_rule_positive_count": len(positive_rules),
        "risk_rule_zero_count": len(risk_rules) - len(positive_rules),
        "risk_rule_high_point_count": len(high_point_rules),

        "risk_category_anomalies": category_counter.get("Anomalies", 0),
        "risk_category_stale_objects": category_counter.get("StaleObjects", 0),
        "risk_category_privileged_accounts": category_counter.get("PrivilegedAccounts", 0),
        "risk_category_trusts": category_counter.get("Trusts", 0),

        "risk_rule_score_20": point_counter.get("20", 0),
        "risk_rule_score_15": point_counter.get("15", 0),
        "risk_rule_score_10": point_counter.get("10", 0),
        "risk_rule_score_5": point_counter.get("5", 0),
        "risk_rule_score_1": point_counter.get("1", 0),
        "risk_rule_score_0": point_counter.get("0", 0),

        "risk_ids": [r["risk_id"] for r in risk_rules if r["risk_id"]],
        "risk_items": risk_rules,
        "top_risks": sorted(
            positive_rules,
            key=lambda x: x.get("points", 0),
            reverse=True
        )[:10],
    })

    return summary


artifacts = []

html_artifact = make_artifact(html_path, "text/html")
xml_artifact = make_artifact(xml_path, "application/xml")

if html_artifact:
    artifacts.append(html_artifact)
if xml_artifact:
    artifacts.append(xml_artifact)

parsed_xml_summary = parse_pingcastle_xml(xml_path)

summary = {
    "domain": domain,
    "target_ip": target_ip,
    "status": "success",
    "html_report": os.path.basename(html_path) if html_artifact else None,
    "xml_report": os.path.basename(xml_path) if xml_artifact else None,
    "html_generated": bool(html_artifact),
    "xml_generated": bool(xml_artifact),
}

summary.update(parsed_xml_summary)

payload = {
    "tool": "pingcastle",
    "query_type": "ad_healthcheck",
    "run_id": run_id,
    "summary": summary,
    "raw": {
        "html_path_on_attack_runner": html_path,
        "xml_path_on_attack_runner": xml_path,
    },
    "artifacts": artifacts,
}

data = json.dumps(payload, ensure_ascii=False).encode("utf-8")

req = urllib.request.Request(
    f"{backend_url}/recon-results",
    data=data,
    headers={"Content-Type": "application/json"},
    method="POST",
)

try:
    with urllib.request.urlopen(req, timeout=20) as res:
        body = res.read().decode("utf-8", errors="replace")
        print("[INFO] backend upload response:", body)
except Exception as exc:
    print("[WARN] failed to upload recon result:", exc)
PY

elif [ "$FINAL_RC" -eq 0 ]; then
  echo "[WARN] BACKEND_URL/backend_url is empty. Skipping recon result upload."
fi



exit "$FINAL_RC"