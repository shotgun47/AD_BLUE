import json
from typing import List, Dict, Any, Optional

from analysis.event_normalizer import normalize_event
from analysis.detection_engine import evaluate_event
from analysis.risk_engine import calculate_risk

def build_default_detection() -> dict:
    return {
        "detected": False,
        "rule_id": None,
        "rule_name": None,
        "reason": [],
        "attack_tactic": None,
        "attack_technique": None,
        "response_guide": [],
        "all_rules": [] # 어떤 룰들에 걸렸는지 전체 ID 저장용 (선택사항)
    }

def build_event_bundle(event: Any, recent_events: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    if recent_events is None:
        recent_events = []

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
    }

    normalized = normalize_event(event)

    # 3. 탐지 엔진 실행 (리스트 결과 수신)
    detection_results = evaluate_event(
        event_dict=event_dict,
        normalized=normalized,
        recent_events=recent_events,
    )

    # 4. 탐지 결과 구조화 및 통합
    detection = build_default_detection()
    if detection_results:
        detection["detected"] = True
        
        # 가독성을 위해 가장 위험도가 높거나 첫 번째인 룰 정보를 대표로 설정
        primary = detection_results[0]
        detection["rule_id"] = primary.get("rule_id")
        detection["rule_name"] = primary.get("rule_name")
        detection["attack_tactic"] = primary.get("attack_tactic")
        detection["attack_technique"] = primary.get("attack_technique")

        for res in detection_results:
            # 사유와 대응 가이드를 리스트로 합침
            if res.get("reason"):
                detection["reason"].extend(res.get("reason") if isinstance(res.get("reason"), list) else [res.get("reason")])
            if res.get("response_guide"):
                detection["response_guide"].extend(res.get("response_guide"))
            # 걸린 모든 룰 ID 기록
            detection["all_rules"].append(res.get("rule_id"))

        # 중복 제거
        detection["reason"] = list(set(detection["reason"]))
        detection["response_guide"] = list(set(detection["response_guide"]))

    # 5. 위험도 계산
    risk = calculate_risk(event, normalized, detection)

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