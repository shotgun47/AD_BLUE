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
        "rule_score": 0,
        "reason": [],
        "attack_tactic": None,
        "attack_technique": None,
        "response_guide": [],
        "all_rules": [] 
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
        # AS-REP Roasting 탐지를 위한 필드 (정규화 단계에서 추출됨)
        "pre_auth_type": getattr(event, 'pre_auth_type', None),
        "ticket_encryption_type": getattr(event, 'ticket_encryption_type', None),
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
        
        # 가독성을 위해 첫 번째 탐지 결과를 대표 정보로 설정
        primary = detection_results[0]
        detection["rule_id"] = primary.get("rule_id")
        detection["rule_name"] = primary.get("rule_name")
        detection["attack_tactic"] = primary.get("attack_tactic")
        detection["attack_technique"] = primary.get("attack_technique")

        for res in detection_results:
            # 사유(reason) 통합
            r = res.get("reason", [])
            detection["reason"].extend(r if isinstance(r, list) else [r])
            
            # 대응 가이드(response_guide) 통합
            g = res.get("response_guide", [])
            detection["response_guide"].extend(g if isinstance(g, list) else [g])
            
            # 탐지된 모든 룰 ID 기록
            detection["all_rules"].append(res.get("rule_id"))

        # 중복 제거 (set 활용)
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