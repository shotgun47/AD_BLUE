import os
import json
import uuid
import sqlite3
import subprocess
import threading
from datetime import datetime
from typing import Dict, Any, List
from fastapi import HTTPException

from app.config import SCENARIO_BASE_DIR, LOG_BASE_DIR, SCENARIO_RUNS_DB_PATH


RUN_STATUS: Dict[str, dict] = {}


def ensure_dirs():
    os.makedirs(LOG_BASE_DIR, exist_ok=True)
    os.makedirs(SCENARIO_BASE_DIR, exist_ok=True)
    init_run_db()


def scenario_id_to_path(scenario_id: str) -> str:
    return os.path.join(SCENARIO_BASE_DIR, f"{scenario_id}.sh")


def path_to_scenario_id(path: str) -> str:
    name = os.path.basename(path)
    if name.endswith(".sh"):
        return name[:-3]
    return name


def label_from_scenario_id(scenario_id: str) -> str:
    return scenario_id.replace("_", " ").title()


def scenario_meta_path(scenario_id: str) -> str:
    return os.path.join(SCENARIO_BASE_DIR, f"{scenario_id}.meta.json")


def load_scenario_meta(scenario_id: str) -> dict:
    path = scenario_meta_path(scenario_id)

    if not os.path.exists(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}



def list_scenarios() -> List[dict]:
    ensure_dirs()
    items = []

    for name in sorted(os.listdir(SCENARIO_BASE_DIR)):
        if not name.endswith(".sh"):
            continue

        full_path = os.path.join(SCENARIO_BASE_DIR, name)
        if not os.path.isfile(full_path):
            continue

        scenario_id = path_to_scenario_id(full_path)
        meta = load_scenario_meta(scenario_id)

        label = meta.get("label") or label_from_scenario_id(scenario_id)
        params_schema = meta.get("params_schema", [])
        scenario_type = meta.get("scenario_type", "general")

        description = meta.get("description")

        if not description:

            if params_schema:
                description = "추가 파라미터 입력 가능"
            else:
                description = f"{scenario_id} 시나리오"

        items.append({
            "scenario_id": scenario_id,
            "label": label,
            "description": description,
            "params_schema": params_schema,
            "scenario_type": scenario_type,
        })

    return items


def _watch_process(run_id: str, process: subprocess.Popen):
    return_code = process.wait()

    item = RUN_STATUS.get(run_id)
    if not item:
        return

    item["finished_at"] = datetime.utcnow().isoformat()
    item["return_code"] = return_code

    if return_code == 0:
        item["status"] = "success"
    else:
        item["status"] = "failed"

    save_run_finished(item)


def run_scenario(scenario_id: str, request_id: str | None, params: Dict[str, Any] | None):
    ensure_dirs()

    target_ip = (params or {}).get("target_ip")
    if target_ip:
        conflict = has_running_target_conflict(target_ip)
        if conflict:
            raise ValueError(
                f"Target already in use: {target_ip} "
                f"(run_id={conflict.get('run_id')}, "
                f"scenario={conflict.get('scenario_id')}, "
                f"requested_by={conflict.get('requested_by')})"
            )


    script_path = scenario_id_to_path(scenario_id)

    if not os.path.exists(script_path):
        raise FileNotFoundError("Scenario script not found")

    meta = load_scenario_meta(scenario_id)
    scenario_type = meta.get("scenario_type", "general")

    run_id = request_id or f"run-{uuid.uuid4().hex[:8]}"
    log_path = os.path.join(LOG_BASE_DIR, f"{run_id}.log")

    params_json = json.dumps(params or {}, ensure_ascii=False)

    with open(log_path, "w", encoding="utf-8") as logf:
        process = subprocess.Popen(
            ["bash", script_path, run_id, params_json],
            stdout=logf,
            stderr=logf,
            cwd=SCENARIO_BASE_DIR
        )

    status = {
        "run_id": run_id,
        "target_ip": (params or {}).get("target_ip"),
        "scenario_id": scenario_id,
        "scenario_type": scenario_type,
        "requested_by": (params or {}).get("requested_by"),
        "status": "running",
        "started_at": datetime.utcnow().isoformat(),
        "finished_at": None,
        "return_code": None,
        "pid": process.pid,
        "log_path": log_path,
    }

    RUN_STATUS[run_id] = status
    save_run_started(status)

    watcher = threading.Thread(
        target=_watch_process,
        args=(run_id, process),
        daemon=True
    )
    watcher.start()

    return status


def get_status(run_id: str):
    item = RUN_STATUS.get(run_id)
    if item:
        return item

    conn = sqlite3.connect(SCENARIO_RUNS_DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM scenario_runs WHERE run_id = ?", (run_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def has_running_target_conflict(target_ip: str) -> dict | None:
    for item in RUN_STATUS.values():
        if item.get("status") == "running" and item.get("target_ip") == target_ip:
            return item
    return None


def init_run_db():
    db_dir = os.path.dirname(SCENARIO_RUNS_DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(SCENARIO_RUNS_DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scenario_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT UNIQUE,
            scenario_id TEXT,
            scenario_type TEXT,
            requested_by TEXT,
            target_ip TEXT,
            status TEXT,
            started_at TEXT,
            finished_at TEXT,
            return_code INTEGER,
            log_path TEXT
        )
    """)

    # 기존 테이블 예외처리
    try:
        cur.execute("ALTER TABLE scenario_runs ADD COLUMN scenario_type TEXT DEFAULT 'general'")
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()


def save_run_started(status: dict):
    conn = sqlite3.connect(SCENARIO_RUNS_DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT OR REPLACE INTO scenario_runs (
            run_id, scenario_id, scenario_type, requested_by, target_ip,
            status, started_at, finished_at, return_code, log_path
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        status.get("run_id"),
        status.get("scenario_id"),
        status.get("scenario_type", "general"),
        status.get("requested_by"),
        status.get("target_ip"),
        status.get("status"),
        status.get("started_at"),
        status.get("finished_at"),
        status.get("return_code"),
        status.get("log_path"),
    ))
    conn.commit()
    conn.close()


def save_run_finished(item: dict):
    conn = sqlite3.connect(SCENARIO_RUNS_DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        UPDATE scenario_runs
        SET status = ?, finished_at = ?, return_code = ?, log_path = ?
        WHERE run_id = ?
    """, (
        item.get("status"),
        item.get("finished_at"),
        item.get("return_code"),
        item.get("log_path"),
        item.get("run_id"),
    ))
    conn.commit()
    conn.close()


def list_run_history(limit: int = 5):
    conn = sqlite3.connect(SCENARIO_RUNS_DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("""
        SELECT *
        FROM scenario_runs
        ORDER BY started_at DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def list_running_runs():
    conn = sqlite3.connect(SCENARIO_RUNS_DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("""
        SELECT *
        FROM scenario_runs
        WHERE status = 'running'
        ORDER BY started_at DESC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def get_run_log(run_id: str, tail: int = 200):
    item = get_status(run_id)
    if not item:
        raise HTTPException(status_code=404, detail="Run not found")

    log_path = item.get("log_path")
    if not log_path or not os.path.exists(log_path):
        return {
            "result": "error",
            "message": "Log file not found",
            "run_id": run_id,
            "log_path": log_path,
        }

    try:
        with open(log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        encoding = "utf-8"
    except UnicodeDecodeError:
        with open(log_path, "r", encoding="cp949", errors="replace") as f:
            lines = f.readlines()
        encoding = "cp949"

    tail = max(1, min(int(tail), 2000))
    sliced = lines[-tail:]

    return {
        "result": "ok",
        "run_id": run_id,
        "scenario_id": item.get("scenario_id"),
        "scenario_type": item.get("scenario_type", "general"),
        "status": item.get("status"),
        "log_path": log_path,
        "encoding": encoding,
        "tail": tail,
        "log_text": "".join(sliced),
    }
ubuntu@attack-machine:~/attack-runner/app$ cat main.py
from fastapi import FastAPI, Header, HTTPException

from app.config import ATTACK_RUNNER_TOKEN
from app.models import RunScenarioRequest
from app.runner import run_scenario, get_status, list_scenarios, list_run_history, list_running_runs, get_run_log

app = FastAPI(title="Attack Runner")


def verify_token(x_api_token: str | None):
    if x_api_token != ATTACK_RUNNER_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/scenario/list")
def scenario_list(x_api_token: str | None = Header(default=None)):
    verify_token(x_api_token)
    return list_scenarios()


@app.post("/run-scenario")
def run_scenario_api(req: RunScenarioRequest, x_api_token: str | None = Header(default=None)):
    verify_token(x_api_token)

    try:
        result = run_scenario(req.scenario_id, req.request_id, req.params)
        return {
            "result": "accepted",
            "run_id": result["run_id"],
            "status": result["status"],
            "scenario_id": result["scenario_id"],
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")


@app.get("/status/{run_id}")
def status_api(run_id: str, x_api_token: str | None = Header(default=None)):
    verify_token(x_api_token)

    item = get_status(run_id)
    if not item:
        raise HTTPException(status_code=404, detail="run_id not found")
    return item


@app.get("/scenario-runs")
def scenario_runs(limit: int = 5, x_api_token: str | None = Header(default=None)):
    verify_token(x_api_token)
    return list_run_history(limit)


@app.get("/scenario-runs/running")
def scenario_runs_running(x_api_token: str | None = Header(default=None)):
    verify_token(x_api_token)
    return list_running_runs()


@app.get("/logs/{run_id}")
def logs_api(run_id: str, tail: int = 200, x_api_token: str | None = Header(default=None)):
    verify_token(x_api_token)
    return get_run_log(run_id, tail)