import os
import uuid
import requests

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