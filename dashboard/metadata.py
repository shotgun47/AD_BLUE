# dashboard/metadata.py

EVENT_CATALOG = {
    "1": {
        "type": "process_create",
        "label": "Sysmon 프로세스 생성",
        "description": "새 프로세스가 실행된 흔적입니다.",
        "source": "Sysmon",
        "category": "프로세스",
        "attack_tactic": "Execution",
        "attack_technique": "T1059",
    },
    "3": {
        "type": "network_connection",
        "label": "Sysmon 네트워크 연결",
        "description": "프로세스가 네트워크 연결을 시도한 흔적입니다.",
        "source": "Sysmon",
        "category": "네트워크",
        "attack_tactic": "Command and Control",
        "attack_technique": "Application Layer Protocol",
    },
    "7": {
        "type": "image_loaded",
        "label": "Sysmon 이미지/DLL 로드",
        "description": "프로세스가 DLL 또는 이미지를 로드한 흔적입니다.",
        "source": "Sysmon",
        "category": "프로세스",
        "attack_tactic": "Defense Evasion",
        "attack_technique": "Hijack Execution Flow",
    },
    "11": {
        "type": "file_create",
        "label": "Sysmon 파일 생성",
        "description": "프로세스가 파일을 생성한 흔적입니다.",
        "source": "Sysmon",
        "category": "파일",
        "attack_tactic": "Defense Evasion",
        "attack_technique": "Masquerading",
    },
    "12": {
        "type": "registry_object_change",
        "label": "Sysmon 레지스트리 객체 변경",
        "description": "레지스트리 키 생성 또는 삭제 흔적입니다.",
        "source": "Sysmon",
        "category": "레지스트리",
        "attack_tactic": "Persistence",
        "attack_technique": "Registry Run Keys / Startup Folder",
    },
    "13": {
        "type": "registry_value_set",
        "label": "Sysmon 레지스트리 값 설정",
        "description": "레지스트리 값이 설정 또는 변경된 흔적입니다.",
        "source": "Sysmon",
        "category": "레지스트리",
        "attack_tactic": "Persistence",
        "attack_technique": "Registry Run Keys / Startup Folder",
    },
    "14": {
        "type": "registry_value_rename",
        "label": "Sysmon 레지스트리 값 이름 변경",
        "description": "레지스트리 값 이름이 변경된 흔적입니다.",
        "source": "Sysmon",
        "category": "레지스트리",
        "attack_tactic": "Persistence",
        "attack_technique": "Registry Run Keys / Startup Folder",
    },
    "22": {
        "type": "dns_query",
        "label": "Sysmon DNS 질의",
        "description": "프로세스가 DNS 질의를 수행한 흔적입니다.",
        "source": "Sysmon",
        "category": "DNS",
        "attack_tactic": "Command and Control",
        "attack_technique": "DNS",
    },

    "4103": {
        "type": "powershell_module",
        "label": "PowerShell 모듈 로깅",
        "description": (
            "PowerShell 명령 실행 과정에서 모듈 또는 cmdlet 호출 정보가 기록된 이벤트입니다. "
            "정찰 도구 실행, 원격 PowerShell 사용, AD 관련 cmdlet 호출 흐름을 확인하는 데 활용됩니다."
        ),
        "source": "Microsoft-Windows-PowerShell/Operational",
        "category": "PowerShell",
        "attack_tactic": "Execution",
        "attack_technique": "T1059.001",
    },
    "4104": {
        "type": "powershell_script_block",
        "label": "PowerShell ScriptBlock 실행",
        "description": (
            "PowerShell에서 실행된 스크립트 블록 내용이 기록된 이벤트입니다. "
            "4688 프로세스 생성 로그만으로는 보이지 않는 PowerView 함수 호출, "
            "Invoke-Command, 원격 실행 스크립트, PingCastle 실행 구문 등을 확인할 수 있습니다."
        ),
        "source": "Microsoft-Windows-PowerShell/Operational",
        "category": "PowerShell",
        "attack_tactic": "Execution",
        "attack_technique": "T1059.001",
    },
    "4624": {
        "type": "login_success",
        "label": "로그인 성공",
        "description": "Windows 계정 로그온이 성공한 이벤트입니다.",
        "source": "Windows Security",
        "category": "인증",
        "attack_tactic": "Initial Access",
        "attack_technique": "Valid Accounts",
    },
    "4625": {
        "type": "login_failure",
        "label": "로그인 실패",
        "description": "Windows 계정 로그온이 실패한 이벤트입니다.",
        "source": "Windows Security",
        "category": "인증",
        "attack_tactic": "Credential Access",
        "attack_technique": "Brute Force",
    },
    "4634": {
        "type": "logoff",
        "label": "로그오프",
        "description": "사용자 세션이 종료된 이벤트입니다.",
        "source": "Windows Security",
        "category": "인증",
        "attack_tactic": "None",
        "attack_technique": "Logoff Event",
    },
    "4648": {
        "type": "explicit_credentials_logon",
        "label": "명시적 자격 증명 사용",
        "description": "다른 계정의 자격 증명을 명시적으로 사용한 로그온 이벤트입니다.",
        "source": "Windows Security",
        "category": "인증",
        "attack_tactic": "Lateral Movement",
        "attack_technique": "Alternate Authentication Material",
    },
    "4672": {
        "type": "special_privilege_logon",
        "label": "특권 로그온",
        "description": "관리자급 특권이 부여된 계정이 로그온한 이벤트입니다.",
        "source": "Windows Security",
        "category": "권한",
        "attack_tactic": "Privilege Escalation",
        "attack_technique": "Valid Accounts",
    },
    "4688": {
        "type": "process_create",
        "label": "Windows 프로세스 생성",
        "description": "Windows 보안 로그 기준의 프로세스 생성 이벤트입니다.",
        "source": "Windows Security",
        "category": "프로세스",
        "attack_tactic": "Execution",
        "attack_technique": "T1059",
    },

    "4720": {
        "type": "account_created",
        "label": "계정 생성",
        "description": "새 사용자 계정이 생성된 이벤트입니다.",
        "source": "Windows Security",
        "category": "계정 관리",
        "attack_tactic": "Persistence",
        "attack_technique": "Create Account",
    },
    "4722": {
        "type": "account_enabled",
        "label": "계정 활성화",
        "description": "비활성화되어 있던 계정이 활성화된 이벤트입니다.",
        "source": "Windows Security",
        "category": "계정 관리",
        "attack_tactic": "Persistence",
        "attack_technique": "Account Manipulation",
    },
    "4723": {
        "type": "password_change",
        "label": "비밀번호 변경",
        "description": "사용자가 자신의 비밀번호를 변경한 이벤트입니다.",
        "source": "Windows Security",
        "category": "계정 관리",
        "attack_tactic": "Credential Access",
        "attack_technique": "Password Change",
    },
    "4724": {
        "type": "password_reset",
        "label": "비밀번호 재설정",
        "description": "관리자 또는 권한 있는 사용자가 다른 계정의 비밀번호를 재설정한 이벤트입니다.",
        "source": "Windows Security",
        "category": "계정 관리",
        "attack_tactic": "Credential Access",
        "attack_technique": "Account Manipulation",
    },
    "4725": {
        "type": "account_disabled",
        "label": "계정 비활성화",
        "description": "사용자 계정이 비활성화된 이벤트입니다.",
        "source": "Windows Security",
        "category": "계정 관리",
        "attack_tactic": "Defense Evasion",
        "attack_technique": "Account Manipulation",
    },
    "4726": {
        "type": "account_deleted",
        "label": "계정 삭제",
        "description": "사용자 계정이 삭제된 이벤트입니다.",
        "source": "Windows Security",
        "category": "계정 관리",
        "attack_tactic": "Defense Evasion",
        "attack_technique": "Account Manipulation",
    },

    "4728": {
        "type": "group_change",
        "label": "Domain Admins 그룹 멤버 추가",
        "description": "전역 보안 그룹에 멤버가 추가된 이벤트입니다. Domain Admins 변경은 권한 상승과 직접 관련됩니다.",
        "source": "Windows Security",
        "category": "그룹 관리",
        "attack_tactic": "Privilege Escalation",
        "attack_technique": "Account Manipulation",
    },
    "4729": {
        "type": "group_change",
        "label": "Domain Admins 그룹 멤버 제거",
        "description": "전역 보안 그룹에서 멤버가 제거된 이벤트입니다.",
        "source": "Windows Security",
        "category": "그룹 관리",
        "attack_tactic": "Defense Evasion",
        "attack_technique": "Account Manipulation",
    },
    "4732": {
        "type": "group_change",
        "label": "Administrators 로컬 그룹 멤버 추가",
        "description": "로컬 관리자 그룹에 멤버가 추가된 이벤트입니다.",
        "source": "Windows Security",
        "category": "그룹 관리",
        "attack_tactic": "Privilege Escalation",
        "attack_technique": "Account Manipulation",
    },
    "4733": {
        "type": "group_change",
        "label": "Administrators 로컬 그룹 멤버 제거",
        "description": "로컬 관리자 그룹에서 멤버가 제거된 이벤트입니다.",
        "source": "Windows Security",
        "category": "그룹 관리",
        "attack_tactic": "Defense Evasion",
        "attack_technique": "Account Manipulation",
    },
    "4756": {
        "type": "group_change",
        "label": "Enterprise Admins 그룹 멤버 추가",
        "description": "Universal 보안 그룹에 멤버가 추가된 이벤트입니다. Enterprise Admins 변경은 매우 높은 권한 변경입니다.",
        "source": "Windows Security",
        "category": "그룹 관리",
        "attack_tactic": "Privilege Escalation",
        "attack_technique": "Account Manipulation",
    },
    "4757": {
        "type": "group_change",
        "label": "Enterprise Admins 그룹 멤버 제거",
        "description": "Universal 보안 그룹에서 멤버가 제거된 이벤트입니다.",
        "source": "Windows Security",
        "category": "그룹 관리",
        "attack_tactic": "Defense Evasion",
        "attack_technique": "Account Manipulation",
    },

    "4768": {
        "type": "kerberos_request",
        "label": "Kerberos AS-REQ 요청",
        "description": "사용자가 Kerberos 인증 티켓 요청을 보낸 이벤트입니다. AS-REP Roasting 탐지와 관련됩니다.",
        "source": "Windows Security",
        "category": "Kerberos",
        "attack_tactic": "Credential Access",
        "attack_technique": "T1558",
    },
    "4769": {
        "type": "kerberos_request",
        "label": "Kerberos TGS 요청",
        "description": "서비스 티켓을 요청한 이벤트입니다. Kerberoasting 탐지와 관련됩니다.",
        "source": "Windows Security",
        "category": "Kerberos",
        "attack_tactic": "Credential Access",
        "attack_technique": "T1558.003",
    },
    "4771": {
        "type": "kerberos_failure",
        "label": "Kerberos 인증 실패",
        "description": "Kerberos 사전 인증 또는 인증 처리 실패 이벤트입니다.",
        "source": "Windows Security",
        "category": "Kerberos",
        "attack_tactic": "Credential Access",
        "attack_technique": "T1558",
    },
}


EVENT_TYPE_LABELS = {
    "login_success": "로그인 성공",
    "login_failure": "로그인 실패",
    "logoff": "로그오프",
    "explicit_credentials_logon": "명시적 자격 증명 사용",
    "special_privilege_logon": "특권 로그온",
    "process_create": "프로세스 생성",
    "network_connection": "네트워크 연결",
    "image_loaded": "이미지/DLL 로드",
    "file_create": "파일 생성",
    "registry_object_change": "레지스트리 객체 변경",
    "registry_value_set": "레지스트리 값 설정",
    "registry_value_rename": "레지스트리 값 이름 변경",
    "dns_query": "DNS 질의",
    "account_created": "계정 생성",
    "account_enabled": "계정 활성화",
    "password_change": "비밀번호 변경",
    "password_reset": "비밀번호 재설정",
    "account_disabled": "계정 비활성화",
    "account_deleted": "계정 삭제",
    "group_change": "그룹 변경",
    "kerberos_request": "Kerberos 요청",
    "kerberos_failure": "Kerberos 실패",
    "unknown": "알 수 없음",
    "powershell_module": "PowerShell 모듈 로깅",
    "powershell_script_block": "PowerShell ScriptBlock 실행",
}


ATTACK_TACTIC_LABELS = {
    "Initial Access": "초기 접근",
    "Execution": "명령/코드 실행",
    "Persistence": "지속성 확보",
    "Privilege Escalation": "권한 상승",
    "Defense Evasion": "방어 회피",
    "Credential Access": "자격 증명 접근",
    "Discovery": "정찰",
    "Lateral Movement": "수평 이동",
    "Command and Control": "명령제어/외부 통신",
    "Exfiltration": "정보 유출",
    "Impact": "영향",
    "None": "공격 매핑 없음",
    None: "-",
}


SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "none": "None",
}


RECON_RECOMMENDATION_LABELS = {
    "kerberoasting": {
        "title": "Kerberoasting 주의",
        "message": "SPN 등록 계정이 확인되었습니다. Kerberoasting 공격이 시도될 수 있으므로 서비스 계정 비밀번호 정책과 Kerberos 티켓 요청 로그를 주의 깊게 확인하기 바랍니다.",
    },
    "asrep_roasting": {
        "title": "AS-REP Roasting 주의",
        "message": "Kerberos 사전 인증이 비활성화된 계정이 확인되었습니다. AS-REP Roasting 공격이 시도될 수 있으므로 계정 설정과 인증 실패 로그를 점검하기 바랍니다.",
    },
    "dns_admin_abuse": {
        "title": "DNS Admin Abuse 주의",
        "message": "DnsAdmins 그룹 멤버가 확인되었습니다. DNS 서비스 권한을 악용한 권한 상승이 시도될 수 있으므로 그룹 멤버십과 변경 이력을 주의 깊게 확인하기 바랍니다.",
    },
    "privilege_escalation_tracking": {
        "title": "고권한 계정 사용 주의",
        "message": "고권한 그룹 멤버가 확인되었습니다. 관리자 계정 사용 이력, 원격 로그인, 그룹 변경 이벤트를 지속적으로 점검하기 바랍니다.",
    },
    "ad_dacl_abuse": {
        "title": "AD-DACL Abuse 주의",
        "message": "흥미로운 ACL 항목이 확인되었습니다. 권한 위임 설정이 권한 상승 경로로 악용될 수 있으므로 민감 객체의 ACL 상태를 점검하기 바랍니다.",
    },
}


def get_recon_recommendation(rec_key: str) -> dict:
    return RECON_RECOMMENDATION_LABELS.get(
        str(rec_key),
        {
            "title": "정찰 결과 기반 주의 항목",
            "message": str(rec_key),
        },
    )


def get_event_meta(event_id, event_type=None):
    event_id = str(event_id) if event_id is not None else "-"
    meta = EVENT_CATALOG.get(event_id)

    if meta:
        return meta

    event_type = event_type or "unknown"

    return {
        "type": event_type,
        "label": EVENT_TYPE_LABELS.get(event_type, event_type),
        "description": "등록된 설명이 없는 이벤트입니다.",
        "source": "-",
        "category": "-",
        "attack_tactic": None,
        "attack_technique": None,
    }


def get_event_type_label(event_type):
    return EVENT_TYPE_LABELS.get(event_type or "unknown", event_type or "알 수 없음")


def get_attack_tactic_label(tactic):
    return ATTACK_TACTIC_LABELS.get(tactic, tactic or "-")


def get_severity_label(severity):
    return SEVERITY_LABELS.get(str(severity or "none").lower(), severity or "None")