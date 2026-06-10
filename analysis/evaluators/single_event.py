from typing import Any, Dict, Optional

def _get_field_value(field: str, event_dict: Dict[str, Any], normalized: Dict[str, Any]) -> Any:
    # 우선순위: normalized > event_dict (태우님이 정규화해주는 데이터를 우선 신뢰)
    if field in normalized:
        return normalized.get(field)
    return event_dict.get(field)

def _match_conditions(match: Dict[str, Any], event_dict: Dict[str, Any], normalized: Dict[str, Any]) -> bool:
    for field, expected in match.items():
        actual = _get_field_value(field, event_dict, normalized)
        # 타입 불일치 방지를 위해 문자열 비교 또는 직접 비교
        if str(actual) != str(expected):
            return False

        if actual_str != expected_str:
            return False

    return True


def _match_any(match_any: Dict[str, Any], event_dict: Dict[str, Any], normalized: Dict[str, Any]) -> bool:
    for field, candidates in match_any.items():
        actual = _get_field_value(field, event_dict, normalized)

        if actual is None:
            return False

        actual_str = str(actual).lower()
        if actual_str.startswith("%{") and actual_str.endswith("}"):
            return False
        
        normalized_candidates = [str(x).lower() for x in candidates]

        if actual_str not in normalized_candidates:
            actual_basename = actual_str.replace("/", "\\").split("\\")[-1]

            if actual_basename not in normalized_candidates:
                return False

    return True


def _contains_any(contains_any: Dict[str, Any], event_dict: Dict[str, Any], normalized: Dict[str, Any]) -> bool:
    for field, keywords in contains_any.items():
        actual = _get_field_value(field, event_dict, normalized)

        if actual is None:
            return False

        actual_str = str(actual).lower()
        if actual_str.startswith("%{") and actual_str.endswith("}"):
            return False

        normalized_keywords = [str(x).lower() for x in keywords]

        if not any(keyword in actual_str for keyword in normalized_keywords):
            return False

    return True

def evaluate_single_event_rule(
    rule: Dict[str, Any],
    event_dict: Dict[str, Any],
    normalized: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    
    # 1. 룰 매칭 확인
    match = rule.get("match", {})
    match_any = rule.get("match_any", {})
    contains_any = rule.get("contains_any", {})

    is_matched = True

    # 하나라도 조건이 걸려있는데 매칭에 실패하면 False 처리
    if match and not _match_exact(match, event_dict, normalized):
        is_matched = False
    if match_any and not _match_any(match_any, event_dict, normalized):
        is_matched = False
    if contains_any and not _contains_any(contains_any, event_dict, normalized):
        is_matched = False

    # 만약 룰 자체가 없거나 매칭에 실패한 경우
    if not rule or not is_matched:
        # # risk_engine에서 처리 가능한 기본 이벤트 타입(정황 분석 대상)인지 확인
        # event_type = normalized.get("event_type")
        # if event_type in ["login_failure", "login_success"]:
        #     # 룰 매칭은 실패했으나 리스크 엔진으로 넘어가도록 통과 처리 (기본 점수 0으로 세팅)
        #     base_score = 0
        # else:
        #     # 정황 분석 대상도 아니면 기존처럼 탐지 제외(None)
        #     return None
        return None # 매칭 실패시마다 계속 반복될 수 있음 / risk_engine 쪽 처리로 변경
    else:
        # 룰 매칭 성공 시 rule에 정의된 점수 적용
        base_score = int(rule.get("score", 0))

    # 2. 결과 생성을 위한 필드 추출 (대시보드 파싱용)
    rule_id = rule.get("rule_id", "N/A") if is_matched else "N/A"
    rule_name = rule.get("name", "Unknown") if is_matched else "Context-based Baseline Monitoring"

    # detection_ctx = {
    #     "rule_id": rule_id,
    #     "rule_name": rule_name,
    #     "rule_score": base_score
    # }

    # 2. 결과 생성을 위한 필드 추출 (대시보드 파싱용)
    base_score = int(rule.get("score", 0))
    severity = rule.get("severity", "low")
    rule_name = rule.get("name")
    
    # 3. 탐지 사유(reason) 동적 생성
    user = normalized.get("username") or event_dict.get("username", "Unknown")
    computer = normalized.get("computer_name") or event_dict.get("computer_name", "Unknown")
    
    reason = f"[{rule_name}] 탐지: {computer} 호스트에서 {user} 계정에 의해 발생"
    
    # 4. 최종 탐지 객체 반환 (DB 저장 형태와 일치)
    return {
        "detected": True,
        "rule_id": rule.get("rule_id"),
        "rule_name": rule_name,
        "reason": [reason],
        "attack_tactic": rule.get("attack", {}).get("tactic"),
        "attack_technique": rule.get("attack", {}).get("technique"),
        "response_guide": rule.get("response_guide", []),
        "risk": {
            "base_score": base_score,
            "weight": 0, # 단일 이벤트는 가중치 0 (기본값)
            "final_score": base_score,
            "severity": rule.get("severity", "low"),
        },
    }