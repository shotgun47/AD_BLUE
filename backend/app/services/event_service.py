import json
import os
import threading
from datetime import datetime, timedelta

from app.db import get_conn
from analysis.bundle_builder import build_event_bundle
from app.services.scenario_service import list_scenario_runs
from analysis.llm_triage import run_llm_triage, should_run_llm_triage

import logging
logger = logging.getLogger("event_save_policy")

SAVE_EVENT_LOCK = threading.Lock()

EVENT_SAVE_MODE = os.getenv("EVENT_SAVE_MODE", "lab").lower()
EVENT_COLLECTION_PAUSED = False
EVENT_COLLECTION_PAUSE_REASON = ""
EVENT_COLLECTION_PAUSED_AT = None

IMPORTANT_EVENT_IDS = {
    # Windows Security
    "4624",  # 로그인 성공
    "4625",  # 로그인 실패
    "4634",  # 로그오프
    "4648",  # 명시적 자격 증명 사용
    "4672",  # 특권 로그온
    "4688",  # 프로세스 생성
    "4103",  # PowerShell Module Logging
    "4104",  # PowerShell Script Block Logging

    # 계정/그룹 변경
    "4720", "4722", "4723", "4724", "4725", "4726",
    "4728", "4729", "4732", "4733",
    "4756", "4757",

    # Kerberos
    "4768", "4769", "4771",

    # Sysmon
    "1",    # Process Create
    "3",    # Network Connection
    "7",    # Image Loaded
    "11",   # File Create
    "12",   # Registry Object Create/Delete
    "13",   # Registry Value Set
    "14",   # Registry Value Rename
    "22",   # DNS Query
}


# ===============================================
# 유틸 함수
# ===============================================

def _get_detected(bundle: dict) -> bool:
    detection = bundle.get("detection") or {}
    return bool(detection.get("detected"))


def _get_event_id(event) -> str:
    event_id = getattr(event, "event_id", None)

    if event_id is None:
        return ""

    text = str(event_id).strip()

    # Logstash 치환 실패값 방지
    if text.startswith("%{") and text.endswith("}"):
        return ""

    # "1.0" 같은 형태 방지
    if text.endswith(".0"):
        text = text[:-2]

    # "01" 같은 형태 방지
    if text.isdigit():
        text = str(int(text))

    return text

# ------------------------------------------
# 이벤트 수집 중단
# ------------------------------------------

def get_event_collection_state():
    return {
        "paused": EVENT_COLLECTION_PAUSED,
        "reason": EVENT_COLLECTION_PAUSE_REASON,
        "paused_at": EVENT_COLLECTION_PAUSED_AT,
        "mode": EVENT_SAVE_MODE,
    }


def pause_event_collection(reason: str = "manual"):
    global EVENT_COLLECTION_PAUSED
    global EVENT_COLLECTION_PAUSE_REASON
    global EVENT_COLLECTION_PAUSED_AT

    EVENT_COLLECTION_PAUSED = True
    EVENT_COLLECTION_PAUSE_REASON = reason or "manual"
    EVENT_COLLECTION_PAUSED_AT = datetime.utcnow().isoformat()

    return get_event_collection_state()


def resume_event_collection():
    global EVENT_COLLECTION_PAUSED
    global EVENT_COLLECTION_PAUSE_REASON
    global EVENT_COLLECTION_PAUSED_AT

    EVENT_COLLECTION_PAUSED = False
    EVENT_COLLECTION_PAUSE_REASON = ""
    EVENT_COLLECTION_PAUSED_AT = None

    return get_event_collection_state()


def is_event_collection_paused() -> bool:
    return bool(EVENT_COLLECTION_PAUSED)


# ------------------------------------------
# 컨텍스트 
# ------------------------------------------

def get_recent_scenario_runs_for_context(limit: int = 20):
    try:
        runs = list_scenario_runs(limit=limit)
        if isinstance(runs, list):
            return runs
        return []
    except Exception:
        return []


def should_load_scenario_context(event) -> bool:
    event_id = _get_event_id(event)

    # 도구 실행 탐지 가능성이 있는 이벤트만 컨텍스트 조회
    if event_id in {"4688", "1", "3", "22"}:
        return True

    service_name = str(getattr(event, "service_name", "") or "").lower()
    image = str(getattr(event, "image", "") or "").lower()
    command_line = str(getattr(event, "command_line", "") or "").lower()
    message = str(getattr(event, "message", "") or "").lower()

    keywords = [
        "powershell",
        "pwsh",
        "powerview",
        "pingcastle",
        "bloodhound",
        "sharphound",
        "ldap",
    ]

    target_text = " ".join([service_name, image, command_line, message])

    return any(keyword in target_text for keyword in keywords)


def run_llm_triage_for_event(event_row_id: int):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, event_json, normalized_json, detection_json, risk_json
        FROM events
        WHERE id = ?
    """, (event_row_id,))

    row = cur.fetchone()

    if not row:
        conn.close()
        return {
            "result": "not_found",
            "event_row_id": event_row_id,
        }

    try:
        event_dict = json.loads(row["event_json"]) if row["event_json"] else {}
    except Exception:
        event_dict = {}

    try:
        normalized = json.loads(row["normalized_json"]) if row["normalized_json"] else {}
    except Exception:
        normalized = {}

    try:
        detection = json.loads(row["detection_json"]) if row["detection_json"] else {}
    except Exception:
        detection = {}

    try:
        risk = json.loads(row["risk_json"]) if row["risk_json"] else {}
    except Exception:
        risk = {}

    if not should_run_llm_triage(detection, risk):
        risk["llm_triage"] = {
            "enabled": False,
            "called": False,
            "verdict": "not_target",
            "confidence": 0.0,
            "summary": "이 이벤트는 LLM 2차 판단 대상이 아닙니다.",
            "suspicious_points": [],
            "benign_context": [],
            "recommended_action": "기존 룰 탐지 결과를 기준으로 확인하세요.",
            "error": "not_target",
        }

        cur.execute("""
            UPDATE events
            SET risk_json = ?
            WHERE id = ?
        """, (
            json.dumps(risk, ensure_ascii=False),
            event_row_id,
        ))

        conn.commit()
        conn.close()

        return {
            "result": "skipped",
            "reason": "not_target",
            "event_row_id": event_row_id,
            "llm_triage": risk["llm_triage"],
        }

    llm_triage = run_llm_triage(
        event=event_dict,
        normalized=normalized,
        detection=detection,
        risk=risk,
    )

    risk["llm_triage"] = llm_triage

    cur.execute("""
        UPDATE events
        SET risk_json = ?
        WHERE id = ?
    """, (
        json.dumps(risk, ensure_ascii=False),
        event_row_id,
    ))

    conn.commit()
    conn.close()

    return {
        "result": "updated",
        "event_row_id": event_row_id,
        "llm_triage": llm_triage,
    }



# ------------------------------------------
# 저장 모드 (debug, lab, alert)
# ------------------------------------------

def should_store_event(event, bundle: dict) -> bool:
    mode = EVENT_SAVE_MODE
    event_id = _get_event_id(event)
    detected = _get_detected(bundle)

    if mode == "debug":
        return True

    if mode == "alert":
        return detected

    # 기본값: lab
    # 중요 이벤트 ID는 탐지되지 않아도 저장하고,
    # 중요 목록 밖 이벤트라도 탐지되면 저장한다.
    if mode == "lab":
        return detected or event_id in IMPORTANT_EVENT_IDS

    # 잘못된 값이 들어오면 안전하게 lab처럼 동작
    return detected or event_id in IMPORTANT_EVENT_IDS


def get_recent_events_for_detection(conn, current_event_time: str):
    if not current_event_time:
        return []

    try:
        dt = datetime.fromisoformat(current_event_time.replace("Z", "+00:00"))
    except Exception:
        return []

    window_start = (dt - timedelta(minutes=5)).isoformat()

    cur = conn.cursor()
    cur.execute("""
        SELECT event_json, normalized_json
        FROM events
        WHERE event_time >= ?
        ORDER BY id DESC
    """, (window_start,))

    rows = cur.fetchall()

    recent_events = []
    for row in rows:
        try:
            event_part = json.loads(row["event_json"]) if row["event_json"] else {}
        except Exception:
            event_part = {}

        try:
            normalized_part = json.loads(row["normalized_json"]) if row["normalized_json"] else {}
        except Exception:
            normalized_part = {}

        recent_events.append({
            "event": event_part,
            "normalized": normalized_part,
        })

    return recent_events


def get_event_save_policy():
    return {
        "mode": EVENT_SAVE_MODE,
        "important_event_ids": sorted(IMPORTANT_EVENT_IDS, key=lambda x: int(x) if str(x).isdigit() else 999999),
        "important_event_count": len(IMPORTANT_EVENT_IDS),
    }


def list_events(limit: int | None = None, since_minutes: int | None = 60):
    conn = get_conn()
    cur = conn.cursor()

    if since_minutes is not None:
        cutoff = datetime.utcnow() - timedelta(minutes=since_minutes)
        cutoff_text = cutoff.isoformat()

        if limit is None:
            cur.execute("""
                SELECT *
                FROM events
                WHERE event_time >= ?
                ORDER BY id DESC
            """, (cutoff_text,))
        else:
            cur.execute("""
                SELECT *
                FROM events
                WHERE event_time >= ?
                ORDER BY id DESC
                LIMIT ?
            """, (cutoff_text, limit))

    else:
        safe_limit = limit or 100
        cur.execute("""
            SELECT *
            FROM events
            ORDER BY id DESC
            LIMIT ?
        """, (safe_limit,))

    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows



# ===============================================
# 이벤트 저장
# ===============================================

def save_event(event):
    if is_event_collection_paused():
        return {
            "result": "skipped",
            "reason": "event_collection_paused",
            "stored": False,
            "event_id": _get_event_id(event),
            "event_time": getattr(event, "event_time", None),
        }

    with SAVE_EVENT_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        recent_events = get_recent_events_for_detection(conn, event.event_time)

        if should_load_scenario_context(event):
            scenario_runs = get_recent_scenario_runs_for_context(limit=10)
        else:
            scenario_runs = []

        bundle = build_event_bundle(
            event,
            recent_events=recent_events,
            scenario_runs=scenario_runs,
        )

        normalized_event_id = _get_event_id(event)

        if not should_store_event(event, bundle):
            logger.warning(
                "event skipped by save policy: mode=%s raw_event_id=%r normalized_event_id=%r provider=%r channel=%r detected=%r",
                EVENT_SAVE_MODE,
                getattr(event, "event_id", None),
                _get_event_id(event),
                getattr(event, "provider", None),
                getattr(event, "channel", None),
                _get_detected(bundle),
            )


            conn.close()
            return {
                "result": "skipped",
                "mode": EVENT_SAVE_MODE,
                "event_id": normalized_event_id,
                "raw_event_id": getattr(event, "event_id", None),
                "detected": _get_detected(bundle),
                "reason": "event did not match save policy",
            }

        cur.execute("""
            INSERT INTO events (
                event_time, event_id,
                computer_name, username, source_ip,
                group_name, message, raw_json,
                event_json, normalized_json, detection_json, risk_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.event_time,
            event.event_id,
            event.computer_name,
            event.username,
            event.source_ip,
            event.group_name,
            event.message,
            event.raw_json,
            json.dumps(bundle["event"], ensure_ascii=False),
            json.dumps(bundle["normalized"], ensure_ascii=False),
            json.dumps(bundle["detection"], ensure_ascii=False),
            json.dumps(bundle["risk"], ensure_ascii=False),
        ))

        conn.commit()
        conn.close()
        return {"result": "saved"}




# ===============================================
# 이벤트 삭제 
# ===============================================

def delete_all_events():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("DELETE FROM events")
    deleted_count = cur.rowcount if cur.rowcount is not None else 0

    conn.commit()

    # DELETE 후 SQLite 파일 공간 정리
    cur.execute("VACUUM")

    conn.close()

    return {"result": "deleted", "deleted_count": deleted_count}


def delete_event_by_id(event_row_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM events WHERE id = ?", (event_row_id,))
    deleted_count = cur.rowcount if cur.rowcount is not None else 0
    conn.commit()
    conn.close()

    if deleted_count == 0:
        return {"result": "not_found", "event_row_id": event_row_id}

    return {
        "result": "deleted",
        "event_row_id": event_row_id,
        "deleted_count": deleted_count,
    }
