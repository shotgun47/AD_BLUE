import json
import threading
from datetime import datetime, timedelta

from app.db import get_conn
from analysis.bundle_builder import build_event_bundle

SAVE_EVENT_LOCK = threading.Lock()


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


def list_events(limit: int = 50):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM events
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def delete_all_events():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM events")
    deleted_count = cur.rowcount if cur.rowcount is not None else 0
    conn.commit()
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
