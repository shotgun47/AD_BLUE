import json
from typing import List, Dict, Any, Optional

from analysis.event_normalizer import normalize_event
from analysis.detection_engine import evaluate_event
from analysis.risk_engine import calculate_risk

def build_default_detection() -> dict:
    return {
        "detected": False,
        # 대표 탐지 정보: 기존 risk_engine / 기존 대시보드 호환용
        "rule_id": None,
        "rule_name": None,
        "reason": [],
        "attack_tactic": None,
        "attack_technique": None,
        "response_guide": [],
        # 다중 탐지 정보
        "all_rules": [],
        "matched_rules": [],
    }


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _unique_keep_order(values: List[Any]) -> List[Any]:
    result = []
    seen = set()
    for value in values:
        key = json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def _score_value(result: Dict[str, Any]) -> int:
    try:
        return int((result.get("risk") or {}).get("final_score", 0))
    except Exception:
        return 0

def build_event_bundle(
    event: Any,
    recent_events: Optional[List[Dict[str, Any]]] = None,
    scenario_runs: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    if recent_events is None:
        recent_events = []

    if scenario_runs is None:
        scenario_runs = []

    event_dict = {
        "event_time": event.event_time,
        "event_id": str(event.event_id) if event.event_id is not None else None,
        "provider": event.provider,
        "channel": event.channel,
        "level": event.level,
        "computer_name": event.computer_name,
        "username": event.username,
        "source_ip": event.source_ip,
        "target_user": event.target_user,
        "target_host": event.target_host,
        "group_name": event.group_name,
        "logon_type": str(event.logon_type) if event.logon_type is not None else None,
        "service_name": event.service_name,
        "message": event.message,
        # AS-REP Roasting 탐지를 위한 필드 (정규화 단계에서 추출됨)
        "pre_auth_type": getattr(event, 'pre_auth_type', None),
        "ticket_encryption_type": getattr(event, 'ticket_encryption_type', None),

        # Sysmon 확장 필드
        "image": getattr(event, "image", None),
        "command_line": getattr(event, "command_line", None),
        "parent_image": getattr(event, "parent_image", None),
        "parent_command_line": getattr(event, "parent_command_line", None),
        "current_directory": getattr(event, "current_directory", None),
        "user": getattr(event, "user", None),

        "destination_ip": getattr(event, "destination_ip", None),
        "destination_port": getattr(event, "destination_port", None),
        "source_port": getattr(event, "source_port", None),
        "protocol": getattr(event, "protocol", None),

        "image_loaded": getattr(event, "image_loaded", None),
        "signed": getattr(event, "signed", None),
        "signature_status": getattr(event, "signature_status", None),
        "hashes": getattr(event, "hashes", None),

        "target_filename": getattr(event, "target_filename", None),
        "creation_utc_time": getattr(event, "creation_utc_time", None),

        "target_object": getattr(event, "target_object", None),
        "registry_event_type": getattr(event, "registry_event_type", None),
        "details": getattr(event, "details", None),

        "query_name": getattr(event, "query_name", None),
        "query_status": getattr(event, "query_status", None),
        "query_results": getattr(event, "query_results", None),
    }

    normalized = normalize_event(event)
    if normalized.get("service_name"):
        event_dict["service_name"] = normalized["service_name"]
    if normalized.get("group_name"):
        event_dict["group_name"] = normalized["group_name"]

    # 3. 탐지 엔진 실행 (이제 모든 탐지 결과를 리스트로 수신)
    detection_results = evaluate_event(
        event_dict=event_dict,
        normalized=normalized,
        recent_events=recent_events,
    )

    # 4. 탐지 결과 구조화 및 다중 결과 통합
    detection = build_default_detection()
    if detection_results:
        detection["detected"] = True

        # 대표 탐지는 위험 점수가 가장 높은 룰로 선택
        # 기존 risk_engine / 기존 대시보드가 rule_id, rule_name을 참조해도 깨지지 않게 유지
        primary = max(detection_results, key=_score_value)
        detection["rule_id"] = primary.get("rule_id")
        detection["rule_name"] = primary.get("rule_name")
        detection["attack_tactic"] = primary.get("attack_tactic")
        detection["attack_technique"] = primary.get("attack_technique")

        for res in detection_results:
            rule_id = res.get("rule_id")
            rule_name = res.get("rule_name")
            rule_risk = res.get("risk") or {}

            detection["all_rules"].append(rule_id)
            detection["matched_rules"].append({
                "rule_id": rule_id,
                "rule_name": rule_name,
                "reason": _as_list(res.get("reason")),
                "attack_tactic": res.get("attack_tactic"),
                "attack_technique": res.get("attack_technique"),
                "response_guide": _as_list(res.get("response_guide")),
                "risk": rule_risk,
            })

            detection["reason"].extend(_as_list(res.get("reason")))
            detection["response_guide"].extend(_as_list(res.get("response_guide")))

        detection["all_rules"] = _unique_keep_order(detection["all_rules"])
        detection["reason"] = _unique_keep_order(detection["reason"])
        detection["response_guide"] = _unique_keep_order(detection["response_guide"])

    # 5. 위험도 계산
    risk = calculate_risk(
        event=event,
        normalized=normalized,
        detection=detection,
        scenario_runs=scenario_runs,
    )

    risk["llm_triage"] = {
        "enabled": False,
        "called": False,
        "verdict": "not_requested",
        "confidence": 0.0,
        "summary": "LLM 2차 판단이 아직 실행되지 않았습니다.",
        "suspicious_points": [],
        "benign_context": [],
        "recommended_action": "",
        "error": None,
    }

    try:
        original_event = json.loads(event.raw_json) if event.raw_json else {}
    except (TypeError, json.JSONDecodeError):
        original_event = {"raw_text": event.raw_json} if event.raw_json else {}

    return {
        "event": event_dict,
        "normalized": normalized,
        "detection": detection,
        "risk": risk,
        "raw_json": {"original_event": original_event},
    }