import requests
from config import BACKEND_URL


def get_health():
    res = requests.get(f"{BACKEND_URL}/health", timeout=5)
    res.raise_for_status()
    return res.json()


def get_events(limit=None, since_minutes=60):
    params = {}

    if limit is not None:
        params["limit"] = limit

    if since_minutes is not None:
        params["since_minutes"] = since_minutes

    res = requests.get(
        f"{BACKEND_URL}/events",
        params=params,
        timeout=5,
    )
    res.raise_for_status()
    return res.json()


def get_event_save_policy():
    res = requests.get(
        f"{BACKEND_URL}/events/save-policy",
        timeout=5,
    )
    res.raise_for_status()
    return res.json()


def delete_all_events():
    res = requests.delete(f"{BACKEND_URL}/events", timeout=10)
    res.raise_for_status()
    return res.json()


def delete_event(event_row_id: int):
    res = requests.delete(f"{BACKEND_URL}/events/{event_row_id}", timeout=10)
    res.raise_for_status()
    return res.json()


def get_scenario_runs(limit: int = 5):
    res = requests.get(f"{BACKEND_URL}/scenario-runs", params={"limit": limit}, timeout=5)
    res.raise_for_status()
    return res.json()


def get_running_scenario_runs():
    res = requests.get(f"{BACKEND_URL}/scenario-runs/running", timeout=5)
    res.raise_for_status()
    return res.json()


def get_scenarios():
    res = requests.get(f"{BACKEND_URL}/scenario/list", timeout=5)
    res.raise_for_status()
    return res.json()


def run_scenario(scenario_id: str, params: dict):
    res = requests.post(
        f"{BACKEND_URL}/scenario/run",
        json={"scenario_id": scenario_id, "params": params},
        timeout=10,
    )
    res.raise_for_status()
    return res.json()


def get_scenario_log(run_id: str, tail: int = 200):
    res = requests.get(
        f"{BACKEND_URL}/scenario/log/{run_id}",
        params={"tail": tail},
        timeout=10,
    )
    res.raise_for_status()
    return res.json()


def get_latest_recon_summary(tool: str):
    res = requests.get(
        f"{BACKEND_URL}/recon-results/latest/{tool}/summary",
        timeout=5,
    )
    res.raise_for_status()
    return res.json()

def get_latest_recon_result(tool: str):
    res = requests.get(f"{BACKEND_URL}/recon-results/latest/{tool}", timeout=10)
    res.raise_for_status()
    return res.json()