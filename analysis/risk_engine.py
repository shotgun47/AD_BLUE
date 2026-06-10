from datetime import datetime, timedelta
from typing import Any, Optional


CONTEXT_ALLOWED_SCENARIO_TYPES = {"tools", "detection_test"}
CONTEXT_EXCLUDED_SCENARIO_TYPES = {"real_attack"}

TOOL_RULE_IDS = {
    "RULE-101",
    "RULE-102",
    "RULE-103",
    "RULE-104",
    "RULE-105",
    "RULE-106",
    "RULE-107",
    "RULE-108",
    "RULE-109",
}


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def _severity_from_score(score: int) -> str:
    if score >= 90:
        return "critical"   # 당장 격리 및 즉각 대응 필요 (SOC 비상)
    elif score >= 70:
        return "high"       # 침해 징후 농후 (우선 분석)
    elif score >= 40:
        return "medium"     # 이상 행위 주의 단계 (일반 관제)
    elif score > 0:
        return "low"        # 단순 특이 사항
    else:
        return "none"       # 정상 행위


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None

    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _matched_rule_ids(detection: dict) -> set[str]:
    result = set()

    if detection.get("rule_id"):
        result.add(str(detection.get("rule_id")))

    for rule in detection.get("matched_rules") or []:
        rule_id = rule.get("rule_id")
        if rule_id:
            result.add(str(rule_id))

    return result


def _is_tool_detection(detection: dict) -> bool:
    rule_ids = _matched_rule_ids(detection)
    return bool(rule_ids & TOOL_RULE_IDS)


def _is_scenario_time_matched(event_time: Optional[str], run: dict, margin_minutes: int = 5) -> bool:
    event_dt = _parse_time(event_time)
    started_at = _parse_time(run.get("started_at"))
    finished_at = _parse_time(run.get("finished_at"))

    if not event_dt or not started_at:
        return False

    start = started_at - timedelta(minutes=margin_minutes)

    # running 상태거나 finished_at이 없으면 시작 후 30분까지를 임시 실행 구간으로 봄
    if finished_at:
        end = finished_at + timedelta(minutes=margin_minutes)
    else:
        end = started_at + timedelta(minutes=30)

    return start <= event_dt <= end


def _find_related_scenario(event, scenario_runs: list[dict]) -> Optional[dict]:
    event_time = getattr(event, "event_time", None)
    event_source_ip = getattr(event, "source_ip", None)
    event_target_host = getattr(event, "target_host", None)

    for run in scenario_runs or []:
        scenario_type = run.get("scenario_type", "general")

        if scenario_type not in CONTEXT_ALLOWED_SCENARIO_TYPES:
            continue

        if not _is_scenario_time_matched(event_time, run):
            continue

        run_target = run.get("target_ip")

        # target_ip가 비어있으면 시간만으로 매칭
        # 값이 있으면 source_ip 또는 target_host와 느슨하게 비교
        if run_target:
            if run_target not in {event_source_ip, event_target_host, getattr(event, "computer_name", None)}:
                # Windows 로그에서는 source_ip가 비거나 컴퓨터명만 들어오는 경우가 있어
                # 시간대 매칭을 완전히 버리진 않고 약한 매칭으로 둔다.
                pass

        return run

    return None


def _build_base_score(normalized: dict, detection: dict) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    event_type = normalized.get("event_type")

    rule_score = _to_int(detection.get("rule_score"), 0)
    if rule_score:
        score = max(score, rule_score)
        reasons.append(f"대표 룰 점수 반영({rule_score})")

    matched_scores = []
    for rule in detection.get("matched_rules") or []:
        matched_scores.append(_to_int(rule.get("rule_score"), 0))
        matched_scores.append(_to_int((rule.get("risk") or {}).get("final_score"), 0))

    matched_scores = [s for s in matched_scores if s > 0]
    if matched_scores:
        rule_max = max(matched_scores)
        score = max(score, rule_max)
        reasons.append(f"매칭 룰 최고 점수 반영({rule_max})")


    if score == 0:
        if event_type == "login_failure":
            score += 15
            reasons.append("로그인 실패 이벤트 기본 점수")
        elif event_type == "login_success":
            score += 10
            reasons.append("로그인 성공 이벤트 기본 점수")
        elif event_type == "group_change":
            score += 60
            reasons.append("그룹 변경 이벤트 기본 점수")
        elif event_type == "kerberos_request":
            score += 40
            reasons.append("Kerberos 요청 이벤트 기본 점수")
        elif event_type == "process_create":
            score += 20
            reasons.append("프로세스 생성 이벤트 기본 점수")
        elif event_type == "network_connection":
            score += 20
            reasons.append("네트워크 연결 이벤트 기본 점수")

    return min(score, 100), reasons


def _calculate_context_weight(normalized: dict) -> tuple[float, list[str]]:
    weight = 1.0
    reasons = []

    is_privileged = (
        normalized.get("is_privileged")
        or normalized.get("is_privileged_account")
        or normalized.get("is_admin_account")
    )
    is_off_hours = normalized.get("is_off_hours")

    if is_privileged:
        weight += 0.4
        reasons.append("특권/관리자/서비스 계정 관련으로 1.4배 가중")

    if is_off_hours:
        weight += 0.3
        reasons.append("업무 외 시간 발생으로 1.3배 가중")

    return weight, reasons



def calculate_risk(
    event,
    normalized: dict,
    detection: dict,
    scenario_runs: Optional[list[dict]] = None,
) -> dict:
    base_score, base_reasons = _build_base_score(normalized, detection)

    risk_weight, weight_reasons = _calculate_context_weight(normalized)
    weighted_score = min(round(base_score * risk_weight), 100)

    scenario_adjustment = 0
    # final_score = base_score
    # context_weight = 0

    rule_context = {
        "enabled": False,
        "applied": False,
        "verdict": "not_evaluated",
        "summary": "컨텍스트 보정 대상이 아닙니다.",
        "related_scenario": None,
        "reasons": [],
    }

    related_scenario = _find_related_scenario(event, scenario_runs or [])
    related_type = related_scenario.get("scenario_type") if related_scenario else None

    # real_attack은 명시적으로 보정 제외
    if related_type in CONTEXT_EXCLUDED_SCENARIO_TYPES:
        rule_context.update({
            "enabled": True,
            "applied": False,
            "verdict": "real_attack_no_downgrade",
            "summary": "real_attack 시나리오와 관련된 이벤트이므로 컨텍스트 점수 하향을 적용하지 않았습니다.",
            "related_scenario": related_scenario,
            "reasons": ["실제 공격 시나리오는 공격 행위로 판단해야 하므로 오탐 보정 제외"],
        })

    # tools / detection_test만 보정
    elif related_type in CONTEXT_ALLOWED_SCENARIO_TYPES:
        rule_context["enabled"] = True
        rule_context["related_scenario"] = related_scenario

        if related_type == "tools" and _is_tool_detection(detection):
            scenario_adjustment -= 35
            rule_context["reasons"].append("정찰 도구 탐지 룰과 승인된 tools 실행 이력이 시간대상 일치")
            rule_context["verdict"] = "expected_tool_activity"
            rule_context["summary"] = "승인된 정찰 도구 실행으로 인한 탐지 가능성이 높습니다."

        elif related_type == "detection_test":
            scenario_adjustment -= 25
            rule_context["reasons"].append("detection_test 시나리오 실행 이력과 시간대상 일치")
            rule_context["verdict"] = "expected_detection_test"
            rule_context["summary"] = "승인된 탐지 테스트 시나리오로 인한 이벤트 가능성이 높습니다."

        rule_context["applied"] = scenario_adjustment != 0

    # 도구 룰인데 실행 이력이 없으면 오히려 의심도 상승
    elif _is_tool_detection(detection):
        rule_context.update({
            "enabled": True,
            "applied": True,
            "verdict": "unapproved_tool_activity",
            "summary": "정찰 도구 실행으로 보이는 이벤트가 탐지되었지만 승인된 도구 실행 이력이 없습니다.",
            "related_scenario": None,
            "reasons": ["PowerView/PingCastle/BloodHound 계열 탐지 룰 매칭", "동일 시간대 승인된 tools 실행 이력 없음"],
        })
        scenario_adjustment += 10

    final_score = max(0, min(100, weighted_score + scenario_adjustment))
    severity = _severity_from_score(final_score)

    return {
        "rule_id": detection.get("rule_id"),
        "rule_name": detection.get("rule_name"),
        "base_score": base_score,
        "risk_weight": round(risk_weight, 1),
        "weight": round(risk_weight, 1),  # 기존 화면/LLM 호환용
        "weighted_score": weighted_score,
        "scenario_adjustment": scenario_adjustment,
        "final_score": final_score,
        "severity": severity,
        "base_reasons": base_reasons,
        "weight_reasons": weight_reasons,
        "rule_context": rule_context,
    }