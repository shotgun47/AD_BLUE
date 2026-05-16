import json
import os
import threading
from datetime import datetime, timedelta

from app.db import get_conn
from analysis.bundle_builder import build_event_bundle

import logging
logger = logging.getLogger("event_save_policy")

SAVE_EVENT_LOCK = threading.Lock()

EVENT_SAVE_MODE = os.getenv("EVENT_SAVE_MODE", "lab").lower()

IMPORTANT_EVENT_IDS = {
    # Windows Security
    "4624",  # 로그인 성공
    "4625",  # 로그인 실패
    "4634",  # 로그오프
    "4648",  # 명시적 자격 증명 사용
    "4672",  # 특권 로그온
    "4688",  # 프로세스 생성

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


def save_event(event):
    with SAVE_EVENT_LOCK:
        conn = get_conn()
        cur = conn.cursor()

        recent_events = get_recent_events_for_detection(conn, event.event_time)
        bundle = build_event_bundle(event, recent_events=recent_events)

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
