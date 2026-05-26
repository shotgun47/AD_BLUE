import os

ATTACK_RUNNER_TOKEN = os.getenv("ATTACK_RUNNER_TOKEN", "<screat-token>")
SCENARIO_BASE_DIR = os.getenv("SCENARIO_BASE_DIR", "/home/ubuntu/attack-runner/scenarios")
LOG_BASE_DIR = os.getenv("LOG_BASE_DIR", "/home/ubuntu/attack-runner/logs")
SCENARIO_RUNS_DB_PATH = os.getenv(
    "SCENARIO_RUNS_DB_PATH",
    "/home/ubuntu/attack-runner/data/scenario_runs.db"
)