from datetime import datetime, timezone
from typing import Optional, Any
import json
import re
from pathlib import PureWindowsPath
from typing import Optional, Any


def _safe_json_loads(value: Any) -> dict:
    if not value:
        return {}
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}


def _deep_get(data: dict, path: list[str]) -> Any:
    cur = data
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _clean_placeholder(value: Any) -> Optional[Any]:
    if value is None:
        return None

    text = str(value).strip()

    # Logstash 치환 실패 문자열 무시
    # 예: "%{service_name_extracted}", "%{source_ip_extracted}"
    if text.startswith("%{") and text.endswith("}"):
        return None

    # 의미 없는 문자열 무시
    if text.lower() in ("none", "null", "nan", "-"):
        return None

    return value


# --------------------------------------
# 그룹 이름 추출
# --------------------------------------

def _normalize_group_name(value: Any) -> Optional[str]:
    value = _clean_placeholder(value)
    if value is None:
        return None

    text = str(value).strip().strip('"').strip("'")
    if not text:
        return None

    # DN 형태가 들어온 경우 CN만 추출
    # 예: CN=Domain Admins,CN=Users,DC=lab,DC=local
    m = re.search(r"CN=([^,]+)", text, re.IGNORECASE)
    if m:
        text = m.group(1).strip()

    # DOMAIN\Group 또는 BUILTIN\Administrators 형태면 뒤쪽만 사용
    if "\\" in text:
        text = text.split("\\")[-1].strip()

    # UPN/도메인 suffix 형태 방어
    # 예: Domain Admins@lab.local
    if "@" in text:
        text = text.split("@")[0].strip()

    # 한글/별칭 보정
    alias_map = {
        "administrators": "Administrators",
        "administrator": "Administrators",
        "관리자": "Administrators",
        "domain admins": "Domain Admins",
        "domain administrators": "Domain Admins",
        "enterprise admins": "Enterprise Admins",
        "enterprise administrators": "Enterprise Admins",
    }

    lowered = text.lower()
    return alias_map.get(lowered, text)


def _extract_group_name_from_message(message: Optional[str]) -> Optional[str]:
    if not message:
        return None

    patterns = [
        # 영문 Windows Event message
        r"Group Name:\s*(.+)",
        r"Account Name:\s*(.+)",

        # 한글 Windows Event message 가능성
        r"그룹 이름:\s*(.+)",
        r"계정 이름:\s*(.+)",
    ]

    for pattern in patterns:
        m = re.search(pattern, message, re.IGNORECASE)
        if not m:
            continue

        value = m.group(1).strip().splitlines()[0].strip()
        result = _normalize_group_name(value)
        if result:
            return result

    return None


def get_group_name(event) -> Optional[str]:
    """
    4728/4729/4732/4733/4756/4757 그룹 멤버 변경 이벤트에서
    변경 대상 그룹명을 안정적으로 추출한다.

    Windows Security 이벤트에서 그룹명은 보통 TargetUserName에 들어온다.
    """

    # 1) 이미 모델 필드에 group_name이 들어온 경우
    direct = _normalize_group_name(getattr(event, "group_name", None))
    if direct:
        return direct

    # 2) raw_json 안에서 Winlogbeat / 커스텀 구조 탐색
    raw = _safe_json_loads(getattr(event, "raw_json", None))

    candidates = [
        ["winlog", "event_data", "TargetUserName"],
        ["winlog", "event_data", "GroupName"],
        ["winlog", "event_data", "TargetAccountName"],
        ["event_data", "TargetUserName"],
        ["event_data", "GroupName"],
        ["event_data", "TargetAccountName"],
        ["TargetUserName"],
        ["GroupName"],
        ["TargetAccountName"],
    ]

    for path in candidates:
        value = _deep_get(raw, path)
        result = _normalize_group_name(value)
        if result:
            return result

    # 3) message 문자열에서 fallback 추출
    return _extract_group_name_from_message(getattr(event, "message", None))


# --------------------------------------
# 프로세스 이름 추출
# --------------------------------------

def _basename_process(value: Any) -> Optional[str]:
    if not value:
        return None

    text = str(value).strip().strip('"').strip("'")
    if not text:
        return None

    # Logstash 치환 실패 placeholder 무시
    # 예: "%{service_name_extracted}", "%{source_ip_extracted}"
    if text.startswith("%{") and text.endswith("}"):
        return None

    # "None", "null", "-" 같은 의미 없는 값도 무시
    if text.lower() in ("none", "null", "nan", "-"):
        return None

    # 커맨드라인 전체가 들어오는 경우 .exe까지만 사용
    if ".exe" in text.lower():
        idx = text.lower().find(".exe")
        text = text[:idx + 4]

    text = text.replace("/", "\\")

    try:
        name = PureWindowsPath(text).name
    except Exception:
        name = text.split("\\")[-1]

    return name.lower() if name else None


def _extract_new_process_name_from_message(message: Optional[str]) -> Optional[str]:
    if not message:
        return None

    patterns = [
        r"New Process Name:\s*(.+)",
        r"새 프로세스 이름:\s*(.+)",
        r"Process Name:\s*(.+)",
        r"Image:\s*(.+)",
    ]

    for pattern in patterns:
        m = re.search(pattern, message, re.IGNORECASE)
        if not m:
            continue

        value = m.group(1).strip()
        value = value.splitlines()[0].strip()
        result = _basename_process(value)
        if result:
            return result

    return None


def get_process_service_name(event) -> Optional[str]:
    """
    4688 / Sysmon 프로세스 생성 이벤트에서 실행 프로세스명을 안정적으로 추출한다.
    최종 반환값 예: powershell.exe, cmd.exe, wmiprvse.exe
    """

    # 1) 이미 모델 필드에 service_name이 들어온 경우
    direct = _basename_process(getattr(event, "service_name", None))
    if direct:
        return direct

    # 2) raw_json 안에서 Winlogbeat / ECS / 커스텀 구조 탐색
    raw = _safe_json_loads(getattr(event, "raw_json", None))

    candidates = [
        ["winlog", "event_data", "NewProcessName"],
        ["winlog", "event_data", "ProcessName"],
        ["winlog", "event_data", "Image"],
        ["event_data", "NewProcessName"],
        ["event_data", "ProcessName"],
        ["event_data", "Image"],
        ["process", "executable"],
        ["process", "name"],
        ["NewProcessName"],
        ["ProcessName"],
        ["Image"],
    ]

    for path in candidates:
        value = _deep_get(raw, path)
        result = _basename_process(value)
        if result:
            return result

    # 3) message 문자열에서 추출
    return _extract_new_process_name_from_message(getattr(event, "message", None))


def _to_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value)


def get_event_type(event_id: Optional[str]) -> str:
    eid = _to_str(event_id)

    mapping = {
        "1": "process_create",
        "3": "network_connection",
        "7": "image_loaded",
        "11": "file_create",
        "12": "registry_object_change",
        "13": "registry_value_set",
        "14": "registry_value_rename",
        "22": "dns_query",
        "4103": "powershell_module",
        "4104": "powershell_script_block",
        "4624": "login_success",
        "4625": "login_failure",
        "4634": "logoff",
        "4648": "explicit_credentials_logon",
        "4670": "permission_change",
        "4672": "special_privilege",  # [추가] RULE-071 매칭용
        "4688": "process_create",
        "4720": "account_created",
        "4722": "account_enabled",
        "4723": "password_change",
        "4724": "password_reset",
        "4725": "account_disabled",
        "4726": "account_deleted",
        "4728": "group_change",
        "4729": "group_change",
        "4732": "group_change",
        "4733": "group_change",
        "4756": "group_change",
        "4757": "group_change",
        "4768": "kerberos_request",
        "4769": "kerberos_request",
        "4771": "kerberos_failure",
        "4648": "explicit_credentials_logon",
        "4670": "permission_change",
        "4688": "process_create",
    }

    return mapping.get(eid, "unknown")


def get_host_role(computer_name: Optional[str]) -> str:
    if not computer_name:
        return "unknown"

    name = computer_name.lower()

    if "dc" in name or "domaincontroller" in name:
        return "dc"
    if "server" in name or "srv" in name:
        return "server"
    return "client"


def is_admin_name(name: Optional[str]) -> bool:
    if not name:
        return False

    lowered = name.lower()
    admin_keywords = [
        "administrator",
        "admin",
        "domain admin",
        "enterprise admin",
        "krbtgt",
    ]
    return any(keyword in lowered for keyword in admin_keywords)


def get_account_type(username: Optional[str], target_user: Optional[str]) -> str:
    name = target_user or username
    if not name:
        return "unknown"

    lowered = name.lower()

    if name.endswith("$"):
        return "machine"

    service_keywords = ["svc", "service", "sql", "iis", "apache", "backup"]
    if any(keyword in lowered for keyword in service_keywords):
        return "service"

    if is_admin_name(name):
        return "admin"

    return "user"


def is_privileged_account(username: Optional[str], target_user: Optional[str]) -> bool:
    return get_account_type(username, target_user) in ["admin", "service"]


def is_off_hours_time(event_time: Optional[str]) -> bool:
    if not event_time:
        return False

    try:
        dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.hour < 8 or dt.hour >= 20
    except Exception:
        return False


def get_logon_type_name(logon_type: Optional[str]) -> Optional[str]:
    value = _to_str(logon_type)
    if value is None:
        return None

    mapping = {
        "2": "interactive",
        "3": "network",
        "4": "batch",
        "5": "service",
        "7": "unlock",
        "8": "network_cleartext",
        "9": "new_credentials",
        "10": "remote_interactive",
        "11": "cached_interactive",
    }

    return mapping.get(value, "unknown")


def normalize_event(event) -> dict:
    username = _clean_placeholder(getattr(event, "username", None))
    target_user = _clean_placeholder(getattr(event, "target_user", None))
    computer_name = _clean_placeholder(getattr(event, "computer_name", None))
    source_ip = _clean_placeholder(getattr(event, "source_ip", None))
    target_host = _clean_placeholder(getattr(event, "target_host", None))
    logon_type = _clean_placeholder(getattr(event, "logon_type", None))
    event_time = _clean_placeholder(getattr(event, "event_time", None))
    event_id = _clean_placeholder(getattr(event, "event_id", None))
    service_name = get_process_service_name(event)
    group_name = get_group_name(event)


    raw = _safe_json_loads(getattr(event, "raw_json", None))
    # 1. pre_auth_type (RULE-063, 064, 065 대응) -> 정수 혹은 문자열 처리 가능하도록 안전하게 추출
    pre_auth_val = _deep_get(raw, ["winlog", "event_data", "PreAuthType"]) or \
                   _deep_get(raw, ["event_data", "PreAuthType"]) or \
                   getattr(event, "pre_auth_type", None)
    pre_auth_type = int(pre_auth_val) if str(pre_auth_val).isdigit() else pre_auth_val

    # 2. ticket_encryption_type (RULE-074 대응)
    ticket_encryption_type = _to_str(_deep_get(raw, ["winlog", "event_data", "TicketEncryptionType"]) or \
                                     _deep_get(raw, ["event_data", "TicketEncryptionType"]) or \
                                     getattr(event, "ticket_encryption_type", None))

    # 3. command_line (RULE-016 대응)
    command_line = _to_str(_deep_get(raw, ["winlog", "event_data", "CommandLine"]) or \
                           _deep_get(raw, ["event_data", "CommandLine"]) or \
                           _deep_get(raw, ["process", "command_line"]) or \
                           getattr(event, "command_line", None))

    # 4. image (RULE-016, 017, 018, 019, 020, 021, 022, 023 대응용 순수 파일명)
    # YAML 매칭 규칙 상 'powershell.exe'와 같이 소문자 파일명 기반 매칭을 하므로 _basename_process 적용
    image = _basename_process(_deep_get(raw, ["winlog", "event_data", "Image"]) or \
                              _deep_get(raw, ["event_data", "Image"]) or \
                              _deep_get(raw, ["process", "executable"]) or \
                              getattr(event, "image", None))

    # 5. destination_port (RULE-017 대응)
    destination_port = _to_str(_deep_get(raw, ["winlog", "event_data", "DestinationPort"]) or \
                               _deep_get(raw, ["event_data", "DestinationPort"]) or \
                               _deep_get(raw, ["destination", "port"]) or \
                               getattr(event, "destination_port", None))

    # 6. image_loaded (RULE-018 대응) - 경로 탐색용이므로 소문자 변환 유지
    image_loaded = _to_str(_deep_get(raw, ["winlog", "event_data", "ImageLoaded"]) or \
                           _deep_get(raw, ["event_data", "ImageLoaded"]) or \
                           getattr(event, "image_loaded", None))
    if image_loaded:
        image_loaded = image_loaded.lower()

    # 7. target_filename (RULE-019 대응) - 경로 탐색용이므로 소문자 변환 유지
    target_filename = _to_str(_deep_get(raw, ["winlog", "event_data", "TargetFilename"]) or \
                              _deep_get(raw, ["event_data", "TargetFilename"]) or \
                              _deep_get(raw, ["file", "path"]) or \
                              getattr(event, "target_filename", None))
    if target_filename:
        target_filename = target_filename.lower()

    # 8. target_object (RULE-020, 021, 022 대응) - 레지스트리 경로 매칭용 소문자 변환
    target_object = _to_str(_deep_get(raw, ["winlog", "event_data", "TargetObject"]) or \
                            _deep_get(raw, ["event_data", "TargetObject"]) or \
                            _deep_get(raw, ["registry", "path"]) or \
                            getattr(event, "target_object", None))
    if target_object:
        target_object = target_object.lower()

    # 9. query_name (RULE-023 대응) - DNS 질의 도메인명 소문자 변환
    query_name = _to_str(_deep_get(raw, ["winlog", "event_data", "QueryName"]) or \
                         _deep_get(raw, ["event_data", "QueryName"]) or \
                         _deep_get(raw, ["dns", "question", "name"]) or \
                         getattr(event, "query_name", None))
    if query_name:
        query_name = query_name.lower()





    raw = _safe_json_loads(getattr(event, "raw_json", None))
    
    # 1. pre_auth_type (RULE-063, 064, 065 대응) -> 정수 혹은 문자열 처리 가능하도록 안전하게 추출
    pre_auth_val = _deep_get(raw, ["winlog", "event_data", "PreAuthType"]) or \
                   _deep_get(raw, ["event_data", "PreAuthType"]) or \
                   getattr(event, "pre_auth_type", None)
    pre_auth_type = int(pre_auth_val) if str(pre_auth_val).isdigit() else pre_auth_val

    # 2. ticket_encryption_type (RULE-074 대응)
    ticket_encryption_type = _to_str(_deep_get(raw, ["winlog", "event_data", "TicketEncryptionType"]) or \
                                     _deep_get(raw, ["event_data", "TicketEncryptionType"]) or \
                                     getattr(event, "ticket_encryption_type", None))

    # 3. command_line (RULE-016 대응)
    command_line = _to_str(_deep_get(raw, ["winlog", "event_data", "CommandLine"]) or \
                           _deep_get(raw, ["event_data", "CommandLine"]) or \
                           _deep_get(raw, ["process", "command_line"]) or \
                           getattr(event, "command_line", None))

    # 4. image (RULE-016, 017, 018, 019, 020, 021, 022, 023 대응용 순수 파일명)
    # YAML 매칭 규칙 상 'powershell.exe'와 같이 소문자 파일명 기반 매칭을 하므로 _basename_process 적용
    image = _basename_process(_deep_get(raw, ["winlog", "event_data", "Image"]) or \
                              _deep_get(raw, ["event_data", "Image"]) or \
                              _deep_get(raw, ["process", "executable"]) or \
                              getattr(event, "image", None))

    # 5. destination_port (RULE-017 대응)
    destination_port = _to_str(_deep_get(raw, ["winlog", "event_data", "DestinationPort"]) or \
                               _deep_get(raw, ["event_data", "DestinationPort"]) or \
                               _deep_get(raw, ["destination", "port"]) or \
                               getattr(event, "destination_port", None))

    # 6. image_loaded (RULE-018 대응) - 경로 탐색용이므로 소문자 변환 유지
    image_loaded = _to_str(_deep_get(raw, ["winlog", "event_data", "ImageLoaded"]) or \
                           _deep_get(raw, ["event_data", "ImageLoaded"]) or \
                           getattr(event, "image_loaded", None))
    if image_loaded:
        image_loaded = image_loaded.lower()

    # 7. target_filename (RULE-019 대응) - 경로 탐색용이므로 소문자 변환 유지
    target_filename = _to_str(_deep_get(raw, ["winlog", "event_data", "TargetFilename"]) or \
                              _deep_get(raw, ["event_data", "TargetFilename"]) or \
                              _deep_get(raw, ["file", "path"]) or \
                              getattr(event, "target_filename", None))
    if target_filename:
        target_filename = target_filename.lower()

    # 8. target_object (RULE-020, 021, 022 대응) - 레지스트리 경로 매칭용 소문자 변환
    target_object = _to_str(_deep_get(raw, ["winlog", "event_data", "TargetObject"]) or \
                            _deep_get(raw, ["event_data", "TargetObject"]) or \
                            _deep_get(raw, ["registry", "path"]) or \
                            getattr(event, "target_object", None))
    if target_object:
        target_object = target_object.lower()

    # 9. query_name (RULE-023 대응) - DNS 질의 도메인명 소문자 변환
    query_name = _to_str(_deep_get(raw, ["winlog", "event_data", "QueryName"]) or \
                         _deep_get(raw, ["event_data", "QueryName"]) or \
                         _deep_get(raw, ["dns", "question", "name"]) or \
                         getattr(event, "query_name", None))
    if query_name:
        query_name = query_name.lower()

    # 중복 선언된 수입 Type 히팅을 막기 위해 group_name 기본 보정 작업 수행
    # 'domain admins' 등의 문자열을 안전하게 매칭하기 위해 원본 값을 살리되 체크용 로직 보장
    if group_name and group_name.lower() in ("domain admins", "administrators", "enterprise admins"):
        # YAML 파일에 적힌 대소문자 형태에 맞춰 매핑 유연성 확보
        if "domain" in group_name.lower():
            group_name = "Domain Admins"
        elif "enterprise" in group_name.lower():
            group_name = "Enterprise Admins"
        elif "administrators" in group_name.lower():
            group_name = "Administrators"

    return {
        "event_type": get_event_type(event_id),
        "event_id": _to_str(event_id),
        "host_role": get_host_role(computer_name),
        "account_type": get_account_type(username, target_user),
        "is_admin_account": is_admin_name(target_user or username),
        "is_privileged": is_privileged_account(username, target_user),
        "is_off_hours": is_off_hours_time(event_time),
        "username": username,
        "target_user": target_user,
        "group_name": group_name,
        "source_ip": source_ip,
        "computer_name": computer_name,
        "target_host": target_host,
        "service_name": service_name,
        "logon_type": _to_str(logon_type), # RULE-002, 061, 069, 070, 073, 075 등 원본 코드 비교 조건 충족용
        "logon_type_name": get_logon_type_name(logon_type),

        "pre_auth_type": pre_auth_type,
        "ticket_encryption_type": ticket_encryption_type,
        "command_line": command_line,
        "image": image,
        "destination_port": destination_port,
        "image_loaded": image_loaded,
        "target_filename": target_filename,
        "target_object": target_object,
        "query_name": query_name,
    }