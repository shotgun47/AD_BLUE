import json


def safe_json_loads(value, default=None):
    if default is None:
        default = {}

    if not value:
        return default

    if isinstance(value, dict):
        return value

    try:
        return json.loads(value)
    except Exception:
        return default


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def unique_keep_order(values):
    result = []
    seen = set()

    for value in values:
        key = (
            json.dumps(value, ensure_ascii=False, sort_keys=True)
            if isinstance(value, (dict, list))
            else str(value)
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(value)

    return result


def normalize_matched_rules(detection: dict):
    matched_rules = detection.get("matched_rules")
    if isinstance(matched_rules, list) and matched_rules:
        return [rule for rule in matched_rules if isinstance(rule, dict)]

    all_rules = detection.get("all_rules")
    if isinstance(all_rules, list) and all_rules:
        normalized_rules = []
        for idx, rule in enumerate(all_rules):
            if isinstance(rule, dict):
                normalized_rules.append(rule)
            else:
                normalized_rules.append({
                    "rule_id": rule,
                    "rule_name": detection.get("rule_name") if idx == 0 else None,
                    "reason": [],
                    "attack_tactic": None,
                    "attack_technique": None,
                    "response_guide": [],
                    "risk": {},
                })
        return normalized_rules

    if detection.get("rule_id") or detection.get("rule_name"):
        return [{
            "rule_id": detection.get("rule_id"),
            "rule_name": detection.get("rule_name"),
            "reason": as_list(detection.get("reason")),
            "attack_tactic": detection.get("attack_tactic"),
            "attack_technique": detection.get("attack_technique"),
            "response_guide": as_list(detection.get("response_guide")),
            "risk": {},
        }]

    return []


def rule_label(rule: dict):
    rule_id = rule.get("rule_id") or "-"
    rule_name = rule.get("rule_name") or "-"
    return f"{rule_id} / {rule_name}" if rule_name != "-" else str(rule_id)


def is_recon_run(item: dict) -> bool:
    scenario_type = str(item.get("scenario_type", "")).lower()
    scenario_id = str(item.get("scenario_id", "")).lower()

    return (
        scenario_type == "tools"
        or any(k in scenario_id for k in ["powerview", "pingcastle", "bloodhound", "recon"])
    )