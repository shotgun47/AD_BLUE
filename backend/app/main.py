from fastapi import FastAPI,  HTTPException, Body
from typing import List

from app.db import init_db
from app.models import EventIn, ScenarioRunRequest
from app.services.event_service import (
    save_event, 
    list_events,
    delete_all_events,
    delete_event_by_id,
    get_event_save_policy,
)
from app.services.scenario_service import (
    run_scenario,
    get_scenario_status,
    list_scenarios,
    list_scenario_runs,
    list_running_scenario_runs,
    get_scenario_log,
)
from app.services.recon_service import (
    save_recon_result,
    get_latest_recon_result,
    get_latest_recon_summary,
)


app = FastAPI()

@app.on_event("startup")
def startup():
    init_db()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/events")
def ingest_event(event: EventIn):
    return save_event(event)


@app.get("/events")
def get_events(limit: int | None = None, since_minutes: int | None = 60):
    return list_events(limit=limit, since_minutes=since_minutes)


@app.get("/events/save-policy")
def event_save_policy():
    return get_event_save_policy()


@app.delete("/events")
def delete_events_all():
    return delete_all_events()


@app.delete("/events/{event_row_id}")
def delete_single_event(event_row_id: int):
    result = delete_event_by_id(event_row_id)
    if result.get("result") == "not_found":
        raise HTTPException(status_code=404, detail="Event not found")
    return result


# 공격 시나리오 실행
@app.post("/scenario/run")
def run_scenario_api(req: ScenarioRunRequest):
    return run_scenario(req)
    

@app.get("/scenario/status/{run_id}")
def scenario_status(run_id: str):
    return get_scenario_status(run_id)


@app.get("/scenario/log/{run_id}")
def scenario_log(run_id: str, tail: int = 200):
    return get_scenario_log(run_id, tail=tail)
    

@app.get("/scenario/list")
def scenario_list():
    return list_scenarios()


@app.get("/scenario-runs")
def scenario_runs(limit: int = 5):
    return list_scenario_runs(limit)
    

@app.get("/scenario-runs/running")
def scenario_runs_running():
    return list_running_scenario_runs()


# recon Result

@app.post("/recon-results")
def ingest_recon_result(payload: dict = Body(...)):
    return save_recon_result(payload)


@app.get("/recon-results/latest/{tool}")
def latest_recon_result(tool: str):
    return get_latest_recon_result(tool)


@app.get("/recon-results/latest/{tool}/summary")
def latest_recon_summary(tool: str):
    return get_latest_recon_summary(tool)