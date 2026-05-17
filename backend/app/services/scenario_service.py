import os
import uuid
import requests
from datetime import datetime, timedelta



ATTACK_RUNNER_URL = os.getenv("ATTACK_RUNNER_URL", "")
ATTACK_RUNNER_TOKEN = os.getenv("ATTACK_RUNNER_TOKEN", "")
BACKEND_IP = os.getenv("BACKEND_IP", "").rstrip("/")

def _auth_headers():
    return {"X-API-Token": ATTACK_RUNNER_TOKEN}


def run_scenario(req):
    if not ATTACK_RUNNER_URL:
        return {"result": "error", "message": "ATTACK_RUNNER_URL is not configured"}

    run_id = f"run-{uuid.uuid4().hex[:8]}"

    _params = req.params or {}

    if BACKEND_IP and not _params.get("backend_url"):
        _params["backend_url"] = BACKEND_IP

    body = {
        "scenario_id": req.scenario_id,
        "request_id": run_id,
        "target_ip": _params.get("target_ip"),
        "requested_by": _params.get("requested_by"),
        "params": _params
    }

    try:
        res = requests.post(
            f"{ATTACK_RUNNER_URL}/run-scenario",
            json=body,
            headers={"X-API-Token": ATTACK_RUNNER_TOKEN},
            timeout=10
        )

        if res.status_code >= 400:
            try:
                err = res.json()
            except Exception:
                err = {"detail": res.text}

            return {
                "result": "error",
                "message": err.get("detail", "Failed to call attack runner")
            }

        data = res.json()
        return {
            "result": "accepted",
            "run_id": data.get("run_id", run_id),
            "status": data.get("status", "running"),
            "scenario_id": data.get("scenario_id", req.scenario_id)
        }

    except requests.RequestException as e:
        return {"result": "error", "message": f"Failed to call attack runner: {e}"}


def get_scenario_status(run_id: str):
    if not ATTACK_RUNNER_URL:
        return {"result": "error", "message": "ATTACK_RUNNER_URL is not configured"}

    try:
        res = requests.get(
            f"{ATTACK_RUNNER_URL}/status/{run_id}",
            headers={"X-API-Token": ATTACK_RUNNER_TOKEN},
            timeout=10
        )
        res.raise_for_status()
        return res.json()
    except requests.RequestException as e:
        return {"result": "error", "message": f"Failed to get scenario status: {e}"}


def get_scenario_log(run_id: str, tail: int = 200):
    if not ATTACK_RUNNER_URL:
        return {"result": "error", "message": "ATTACK_RUNNER_URL is not configured"}

    try:
        res = requests.get(
            f"{ATTACK_RUNNER_URL}/logs/{run_id}",
            headers=_auth_headers(),
            params={"tail": tail},
            timeout=10
        )
        res.raise_for_status()
        return res.json()
    except requests.RequestException as e:
        return {"result": "error", "message": f"Failed to get scenario log: {e}"}




def list_scenarios():
    if not ATTACK_RUNNER_URL:
        return {"result": "error", "message": "ATTACK_RUNNER_URL is not configured"}

    try:
        res = requests.get(
            f"{ATTACK_RUNNER_URL}/scenario/list",
            headers={"X-API-Token": ATTACK_RUNNER_TOKEN},
            timeout=10
        )
        res.raise_for_status()
        return res.json()
    except requests.RequestException as e:
        return {"result": "error", "message": f"Failed to get scenario list: {e}"}


def list_scenario_runs(limit: int = 5):
    if not ATTACK_RUNNER_URL:
        return {"result": "error", "message": "ATTACK_RUNNER_URL is not configured"}

    try:
        res = requests.get(
            f"{ATTACK_RUNNER_URL}/scenario-runs",
            headers={"X-API-Token": ATTACK_RUNNER_TOKEN},
            params={"limit": limit},
            timeout=3
        )
        res.raise_for_status()
        return res.json()
    except requests.RequestException as e:
        return {"result": "error", "message": f"Failed to get scenario runs: {e}"}


def list_running_scenario_runs():
    if not ATTACK_RUNNER_URL:
        return {"result": "error", "message": "ATTACK_RUNNER_URL is not configured"}

    try:
        res = requests.get(
            f"{ATTACK_RUNNER_URL}/scenario-runs/running",
            headers={"X-API-Token": ATTACK_RUNNER_TOKEN},
            timeout=10
        )
        res.raise_for_status()
        return res.json()
    except requests.RequestException as e:
        return {"result": "error", "message": f"Failed to get running scenario runs: {e}"}
    

# ------------------------------------------
# 시나리오 실행 목록 필터링 
# ------------------------------------------

def _parse_iso_time(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def _is_time_overlapped_with_event(event_time: str, run: dict, margin_minutes: int = 5) -> bool:
    event_dt = _parse_iso_time(event_time)
    started_at = _parse_iso_time(run.get("started_at"))
    finished_at = _parse_iso_time(run.get("finished_at"))

    if not event_dt or not started_at:
        return False

    start = started_at - timedelta(minutes=margin_minutes)

    if finished_at:
        end = finished_at + timedelta(minutes=margin_minutes)
    else:
        end = started_at + timedelta(minutes=30)

    return start <= event_dt <= end


def filter_scenario_runs_for_llm(event_dict: dict, scenario_runs: list[dict]) -> list[dict]:
    """
    LLM에는 tools / detection_test 중 이벤트 시간과 관련 있는 실행 이력만 전달한다.
    real_attack은 제외한다.
    """
    event_time = event_dict.get("event_time")
    allowed_types = {"tools", "detection_test"}

    result = []

    for run in scenario_runs or []:
        scenario_type = run.get("scenario_type", "general")

        if scenario_type not in allowed_types:
            continue

        if event_time and not _is_time_overlapped_with_event(event_time, run):
            continue

        result.append(run)

    return result[:5]