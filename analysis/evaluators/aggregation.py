from typing import Any, Dict, Optional, List
from datetime import datetime, timedelta


def _get_field_value(field: str, event_dict: Dict[str, Any], normalized: Dict[str, Any]) -> Any:
    if field in normalized:
        return normalized.get(field)
    return event_dict.get(field)


def _match_conditions(match: Dict[str, Any], event_dict: Dict[str, Any], normalized: Dict[str, Any]) -> bool:
    for field, expected in match.items():
        actual = _get_field_value(field, event_dict, normalized)
        if actual != expected:
            return False
    return True


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def _build_group_key(
    group_fields: List[str],
    event_dict: Dict[str, Any],
    normalized: Dict[str, Any],
) -> tuple:
    values = []
    for field in group_fields:
        values.append(_get_field_value(field, event_dict, normalized))
    return tuple(values)


def _apply_score_modifiers(
    base_score: int,
    rule: Dict[str, Any],
    event_dict: Dict[str, Any],
    normalized: Dict[str, Any],
) -> Dict[str, Any]:
    weight = 0

    for modifier in rule.get("score_modifiers", []):
        field = modifier.get("field")
        op = modifier.get("op")
        expected = modifier.get("value")
        add_value = int(modifier.get("add", 0))

        actual = _get_field_value(field, event_dict, normalized)

        if op == "eq" and actual == expected:
            weight += add_value

    final_score = base_score + weight

    if final_score >= 80:
        severity = "critical"
    elif final_score >= 60:
        severity = "high"
    elif final_score >= 30:
        severity = "medium"
    elif final_score > 0:
        severity = "low"
    else:
        severity = rule.get("severity", "low")

    return {
        "weight": weight,
        "final_score": final_score,
        "severity": severity,
    }


def evaluate_aggregation_rule(
    rule: Dict[str, Any],
    event_dict: Dict[str, Any],
    normalized: Dict[str, Any],
    recent_events: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    match = rule.get("match", {})
    if not _match_conditions(match, event_dict, normalized):
        return None

    event_time = _parse_time(event_dict.get("event_time"))
    if not event_time:
        return None

    window_minutes = int(rule.get("window", {}).get("minutes", 5))
    threshold_count = int(rule.get("threshold", {}).get("count_gte", 1))
    group_fields = rule.get("group_by", [])

    current_group_key = _build_group_key(group_fields, event_dict, normalized)
    window_start = event_time - timedelta(minutes=window_minutes)

    count = 0
    for item in recent_events:
        item_event = item.get("event", {})
        item_normalized = item.get("normalized", {})

        if not _match_conditions(match, item_event, item_normalized):
            continue

        item_time = _parse_time(item_event.get("event_time"))
        if not item_time:
            continue

        # if item_time < window_start or item_time > event_time:
        #     continue
        window_end = event_time + timedelta(minutes=window_minutes)
        if item_time < window_start or item_time > window_end:
            continue

        item_group_key = _build_group_key(group_fields, item_event, item_normalized)
        if item_group_key != current_group_key:
            continue

        count += 1

    # 현재 이벤트까지 포함
    count += 1

    if count < threshold_count:
        return None

    base_score = int(rule.get("score", 0))
    score_result = _apply_score_modifiers(base_score, rule, event_dict, normalized)

    target_name = event_dict.get("target_user") or event_dict.get("username")

    group_text = ", ".join(group_fields) if group_fields else "전체"
    reason_text = (
        f"[{rule.get('name')}] 탐지: "
        f"{group_text} 기준 {window_minutes}분 내 {count}회 이상 발생"
    )

    return {
        "detected": True,
        "rule_id": rule.get("rule_id"),
        "rule_name": rule.get("name"),
        "reason": [reason_text],
        "attack_tactic": rule.get("attack", {}).get("tactic"),
        "attack_technique": rule.get("attack", {}).get("technique"),
        "response_guide": rule.get("response_guide", []),
        "risk": {
            "base_score": base_score,
            "weight": score_result["weight"],
            "final_score": score_result["final_score"],
            "severity": score_result["severity"],
        },
    }