from typing import Any, Dict, List, Optional

from analysis.rule_loader import load_rules, split_rules_by_type
from analysis.evaluators.single_event import evaluate_single_event_rule
from analysis.evaluators.aggregation import evaluate_aggregation_rule


def evaluate_event(
    event_dict: Dict[str, Any],
    normalized: Dict[str, Any],
    recent_events: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:  # 반환 타입을 List로 고정
    if recent_events is None:
        recent_events = []

    rules = load_rules()
    grouped = split_rules_by_type(rules)
    
    all_detections = []  # 탐지된 모든 결과를 담을 리스트

    # 1) single_event 룰 전체 평가 (AS-REP Roasting 단일 탐지 등)
    for rule in grouped.get("single_event", []):
        result = evaluate_single_event_rule(rule, event_dict, normalized)
        if result:
            all_detections.append(result)

    # 2) aggregation 룰 전체 평가 (AS-REP Roasting 스캐닝/집중 공격 탐지)
    for rule in grouped.get("aggregation", []):
        result = evaluate_aggregation_rule(rule, event_dict, normalized, recent_events)
        if result:
            all_detections.append(result)

    return all_detections