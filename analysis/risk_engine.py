def calculate_risk(event: dict, normalized: dict, detection: dict) -> dict:
    """
    YAML 규칙의 MITRE ATT&CK 베이스 점수와 
    컨텍스트 가중치(특권 계정, 비업무 시간)를 결합하여 최종 위험도를 계산합니다.
    (100점 상한선 및 반올림 처리 적용)
    """
    # 1. YAML 규칙에서 정의한 기본 점수 가져오기 (매칭 안 됐으면 0점)
    base_score = detection.get("rule_score", 0) 
    
    # 시그니처 매칭은 없으나 정황 분석만 필요한 기본 이벤트 처리용 백업 점수
    if base_score == 0:
        event_type = normalized.get("event_type")
        if event_type == "login_failure":
            base_score = 15
        elif event_type == "login_success":
            base_score = 10
        else:
            base_score = 0

    # 2. 리스크 엔진 자체 가중치 배수(Weight) 설정
    weight = 1.0
    
    is_privileged = normalized.get("is_privileged", False)
    is_off_hours = normalized.get("is_off_hours", False)

    if is_privileged:
        weight += 0.4  # 특권 계정 악용 우려 시 +0.4 가산 (1.4배)
        
    if is_off_hours:
        weight += 0.3  # 비업무 시간대(새벽/주말) 행위 시 +0.3 가산 (1.3배)
                       # 두 조건 모두 만족 시 최대 1.7배 가중치 적용

    # 3. 최종 점수 계산 (반올림 적용 및 100점 상한선 고정)
    calculated_score = base_score * weight
    final_score = min(round(calculated_score), 100) 

    # 4. 상한선 100점 기준 임계치 등급 판정 (5단계 세분화)
    if final_score >= 90:
        severity = "critical"   # 당장 격리 및 즉각 대응 필요 (SOC 비상)
    elif final_score >= 70:
        severity = "high"       # 침해 징후 농후 (우선 분석)
    elif final_score >= 40:
        severity = "medium"     # 이상 행위 주의 단계 (일반 관제)
    elif final_score > 0:
        severity = "low"        # 단순 특이 사항
    else:
        severity = "none"       # 정상 행위

    return {
        "rule_id": detection.get("rule_id", "N/A"),
        "rule_name": detection.get("rule_name", "Unknown"),
        "base_score": base_score,
        "weight": round(weight, 1),
        "final_score": final_score,
        "severity": severity,
    }