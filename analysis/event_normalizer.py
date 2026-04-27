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
        "4624": "login_success",
        "4625": "login_failure",
        "4634": "logoff",
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
    group_name = _clean_placeholder(getattr(event, "group_name", None))
    source_ip = _clean_placeholder(getattr(event, "source_ip", None))
    target_host = _clean_placeholder(getattr(event, "target_host", None))
    logon_type = _clean_placeholder(getattr(event, "logon_type", None))
    event_time = _clean_placeholder(getattr(event, "event_time", None))
    event_id = _clean_placeholder(getattr(event, "event_id", None))
    service_name = get_process_service_name(event)

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
        "logon_type_name": get_logon_type_name(logon_type),
    }