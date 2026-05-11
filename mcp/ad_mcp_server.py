import json
import os
import shlex
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List

import requests
from mcp.server.fastmcp import FastMCP


# ──────────────────────────────────────────────
# 목표 1: SSE 서버로 전환
#   - host="0.0.0.0" : 팀원들이 Tailscale IP로 접속 가능
#   - port=8080       : MCP SSE 전용 포트
#
# 팀원 접속 명령어 (각자 PC의 터미널에서 실행):
#   claude mcp add --transport sse ad-lab-agent http://<TAILSCALE_IP>:8080/sse
# ──────────────────────────────────────────────
mcp = FastMCP("AD_Lab_Agent", host="0.0.0.0", port=9000)

ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = ROOT_DIR / "data" / "events.db"
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")
ATTACK_RUNNER_URL = os.getenv("ATTACK_RUNNER_URL", "").rstrip("/")
ATTACK_RUNNER_TOKEN = os.getenv("ATTACK_RUNNER_TOKEN", "")
DEFAULT_TARGET_IP = os.getenv("VICTIM_URL", "").strip()
DEFAULT_REQUESTED_BY = os.getenv("ATTACK_REQUESTED_BY", "").strip()


def _resolve_db_path() -> Path:
    raw = os.getenv("DB_PATH")
    if raw:
        return Path(raw)
    return DEFAULT_DB_PATH


def _candidate_scenario_dirs() -> List[Path]:
    return [
        ROOT_DIR / "attack-runner" / "scenarios",
        ROOT_DIR / "attack_runner" / "scenarios",
        ROOT_DIR / "analysis" / "attack-runner" / "scenarios",
    ]


def _auth_headers() -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if ATTACK_RUNNER_TOKEN:
        headers["X-API-Token"] = ATTACK_RUNNER_TOKEN
    return headers


def _run_scenario_via_backend(scenario_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    backend /scenario/run 호출 공통 helper.
    execute_attack_scenario와 같은 흐름이지만 전용 도구에서 재사용하기 위한 함수.
    """
    if params is None:
        params = {}

    if not isinstance(params, dict):
        return {"result": "error", "message": "params must be dict"}

    body = {
        "scenario_id": scenario_id,
        "params": params,
    }

    try:
        res = requests.post(
            f"{BACKEND_URL}/scenario/run",
            json=body,
            timeout=15,
        )

        if res.status_code >= 400:
            try:
                err_payload = res.json()
            except Exception:
                err_payload = {"detail": res.text}

            return {
                "result": "error",
                "message": (
                    err_payload.get("detail")
                    or err_payload.get("message")
                    or "Backend rejected request"
                ),
                "status_code": res.status_code,
                "backend_url": BACKEND_URL,
            }

        payload = res.json()
        if isinstance(payload, dict):
            payload.setdefault("result", "ok")
            payload.setdefault("backend_url", BACKEND_URL)
            return payload

        return {
            "result": "ok",
            "backend_url": BACKEND_URL,
            "data": payload,
        }

    except requests.RequestException as exc:
        return {
            "result": "error",
            "message": f"Failed to call backend scenario API: {exc}",
            "backend_url": BACKEND_URL,
        }
    

@mcp.tool()
def get_recent_security_logs(limit: int = 20) -> Dict[str, Any]:
    """
    Blue Team용: 최근 보안 이벤트를 빠르게 확인할 때 사용합니다.

    Use this tool when you need the latest security telemetry from the lab
    (for example Sysmon/Event Log ingestions) to triage suspicious behavior,
    verify whether an attack simulation generated detectable artifacts, or
    build a short incident timeline.

    Inputs:
    - limit: number of most recent records to return (recommended 10~200).

    Returns:
    - JSON object containing `result`, `db_path`, `count`, and `events`.
    - `events` is an array ordered by newest first.

    Error behavior:
    - If the SQLite DB file is missing or unreadable, returns `result="error"`
      with a clear message instead of raising an exception.
    """
    if limit <= 0:
        return {"result": "error", "message": "limit must be greater than 0"}

    safe_limit = min(limit, 1000)
    db_path = _resolve_db_path()

    if not db_path.exists():
        return {
            "result": "error",
            "message": f"SQLite DB not found: {db_path}",
            "db_path": str(db_path),
        }

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
                id, event_time, ingested_at, event_id, computer_name, username,
                source_ip, group_name, message, raw_json,
                event_json, normalized_json, detection_json, risk_json
            FROM events
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return {
            "result": "ok",
            "db_path": str(db_path),
            "count": len(rows),
            "events": rows,
        }
    except sqlite3.Error as exc:
        return {
            "result": "error",
            "message": f"SQLite query failed: {exc}",
            "db_path": str(db_path),
        }
    except Exception as exc:
        return {
            "result": "error",
            "message": f"Unexpected error while reading logs: {exc}",
            "db_path": str(db_path),
        }


@mcp.tool()
def get_lab_config() -> Dict[str, Any]:
    """
    랩 기본 설정값을 조회합니다.

    공격 시나리오 실행 전에 이 도구를 호출하여 기본 target_ip와
    requested_by 값을 확인하세요. 사용자가 별도로 지정하지 않으면
    이 값을 파라미터로 사용합니다.

    Returns:
    - default_target_ip  : 기본 공격 대상 IP (VICTIM_URL 환경변수)
    - default_requested_by : 기본 실행자 이름 (ATTACK_REQUESTED_BY 환경변수)
    - backend_url        : 백엔드 URL
    - config_ok          : target_ip와 requested_by가 모두 설정되어 있으면 true
    """
    return {
        "result": "ok",
        "default_target_ip": DEFAULT_TARGET_IP or None,
        "default_requested_by": DEFAULT_REQUESTED_BY or None,
        "backend_url": BACKEND_URL,
        "config_ok": bool(DEFAULT_TARGET_IP and DEFAULT_REQUESTED_BY),
        "warnings": [
            *(["VICTIM_URL 환경변수가 비어있습니다. target_ip를 직접 입력해야 합니다."] if not DEFAULT_TARGET_IP else []),
            *(["ATTACK_REQUESTED_BY 환경변수가 비어있습니다. requested_by를 직접 입력해야 합니다."] if not DEFAULT_REQUESTED_BY else []),
        ],
    }


@mcp.tool()
def list_attack_scenarios() -> Dict[str, Any]:
    """
    Red Team용: 현재 실행 가능한 공격 시나리오를 탐색할 때 사용합니다.

    Use this tool before executing an attack to discover available scenarios,
    read their purpose/description, and inspect required parameters such as
    target_ip, requested_by, credentials, or other scenario-specific fields.

    The tool first scans local scenario metadata files (`*.meta.json`) under
    common directories like `attack-runner/scenarios/`. If local metadata is
    not found, it falls back to the backend API (`/scenario/list`) so agents
    can still operate in containerized or remote runner setups.

    Returns:
    - JSON object with `result`, `source`, `count`, and `scenarios`.
    - Each scenario includes `scenario_id`, `label`, `description`,
      `params_schema`, and optional metadata.
    """
    discovered: List[Dict[str, Any]] = []
    found_dirs: List[str] = []

    for base_dir in _candidate_scenario_dirs():
        if not base_dir.exists():
            continue
        found_dirs.append(str(base_dir))
        for meta_path in sorted(base_dir.rglob("*.meta.json")):
            try:
                with meta_path.open("r", encoding="utf-8") as fp:
                    payload = json.load(fp)
            except Exception:
                continue

            scenario_id = payload.get("scenario_id") or meta_path.stem.replace(".meta", "")
            discovered.append(
                {
                    "scenario_id": scenario_id,
                    "label": payload.get("label", scenario_id),
                    "description": payload.get("description", ""),
                    "params_schema": payload.get("params_schema", []),
                    "scenario_type": payload.get("scenario_type", "general"),
                    "meta_path": str(meta_path),
                }
            )

    if discovered:
        return {
            "result": "ok",
            "source": "local_meta",
            "searched_dirs": found_dirs,
            "count": len(discovered),
            "scenarios": discovered,
        }

    try:
        res = requests.get(f"{BACKEND_URL}/scenario/list", timeout=10)
        res.raise_for_status()
        api_data = res.json()
        if isinstance(api_data, dict) and api_data.get("result") == "error":
            return {
                "result": "error",
                "source": "backend_api",
                "message": api_data.get("message", "Failed to list scenarios"),
            }
        return {
            "result": "ok",
            "source": "backend_api",
            "count": len(api_data) if isinstance(api_data, list) else 0,
            "scenarios": api_data if isinstance(api_data, list) else [],
        }
    except requests.RequestException as exc:
        return {
            "result": "error",
            "source": "none",
            "message": (
                "No local scenario metadata found and backend API call failed: "
                f"{exc}"
            ),
            "searched_dirs": found_dirs,
        }


@mcp.tool()
def execute_attack_scenario(scenario_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Red Team용: 공격 시나리오를 실제로 실행(또는 실행 요청)할 때 사용합니다.

    Use this tool only after selecting a valid scenario from
    `list_attack_scenarios()`, and when you are ready to trigger the lab attack
    workflow. This mirrors the dashboard flow by calling backend
    `POST /scenario/run`, which then forwards execution to Attack Runner.

    Inputs:
    - scenario_id: identifier of the attack scenario.
    - params: scenario parameters dict (for example `target_ip`,
      `requested_by`, and optional scenario-specific fields).

    Returns:
    - JSON response from backend containing fields like `result`, `run_id`,
      `status`, `scenario_id`.
    - On failure, returns `result="error"` with actionable details.
    """
    if not scenario_id or not scenario_id.strip():
        return {"result": "error", "message": "scenario_id is required"}

    if params is None:
        params = {}
    if not isinstance(params, dict):
        return {"result": "error", "message": "params must be a JSON object(dict)"}

    body = {"scenario_id": scenario_id.strip(), "params": params}

    try:
        res = requests.post(
            f"{BACKEND_URL}/scenario/run",
            json=body,
            timeout=15,
        )
        if res.status_code >= 400:
            try:
                err_payload = res.json()
            except Exception:
                err_payload = {"detail": res.text}
            return {
                "result": "error",
                "message": err_payload.get("detail") or err_payload.get("message") or "Backend rejected request",
                "status_code": res.status_code,
                "backend_url": BACKEND_URL,
            }

        response_payload = res.json()
        if isinstance(response_payload, dict):
            response_payload.setdefault("backend_url", BACKEND_URL)
            response_payload.setdefault("result", "ok")
            return response_payload

        return {
            "result": "ok",
            "backend_url": BACKEND_URL,
            "data": response_payload,
        }
    except requests.RequestException as exc:
        if ATTACK_RUNNER_URL:
            try:
                direct_res = requests.post(
                    f"{ATTACK_RUNNER_URL}/run-scenario",
                    json={
                        "scenario_id": scenario_id.strip(),
                        "request_id": params.get("request_id"),
                        "params": params,
                    },
                    headers=_auth_headers(),
                    timeout=15,
                )
                if direct_res.status_code >= 400:
                    return {
                        "result": "error",
                        "message": f"Backend and Attack Runner both failed. Backend error: {exc}; Attack Runner status: {direct_res.status_code}",
                    }
                return {
                    "result": "ok",
                    "source": "attack_runner_direct",
                    "backend_error": str(exc),
                    "data": direct_res.json(),
                }
            except requests.RequestException as direct_exc:
                return {
                    "result": "error",
                    "message": f"Failed to execute scenario via backend and direct runner: backend={exc}, direct={direct_exc}",
                    "backend_url": BACKEND_URL,
                    "attack_runner_url": ATTACK_RUNNER_URL,
                }

        return {
            "result": "error",
            "message": f"Failed to call backend scenario API: {exc}",
            "backend_url": BACKEND_URL,
        }


# ══════════════════════════════════════════════════════════════════════
# 목표 2: 커스텀 스킬 템플릿
#
# 아래 함수를 복사해서 새로운 도구를 추가하세요.
# 규칙:
#   1. @mcp.tool() 데코레이터는 반드시 붙일 것
#   2. 파라미터에 Type Hint 필수 (Claude가 파라미터 의미를 파악하는 데 사용)
#   3. 반환 타입은 항상 Dict[str, Any]
#   4. Docstring 첫 줄: "[팀 역할]용: 한 줄 요약"
#   5. result 키: 성공 "ok" / 실패 "error" 로 통일
# ══════════════════════════════════════════════════════════════════════
@mcp.tool()
def filter_sysmon_events(
    event_ids: List[int],
    computer_name: str = "",
    limit: int = 50,
) -> Dict[str, Any]:
    """
    Blue Team용: 특정 Sysmon 이벤트 ID만 필터링하여 조회합니다.

    Use this tool to narrow down security events to specific Windows Event IDs
    (e.g. Sysmon) instead of retrieving all recent logs. Useful for hunting
    process-creation chains (ID 1), network connections (ID 3), or
    credential-access artifacts (ID 10).

    Inputs:
    - event_ids   : 조회할 Event ID 목록. 예) [1, 3, 10]
                    주요 Sysmon ID:
                      1  = Process Create
                      3  = Network Connection
                      7  = Image Loaded (DLL)
                      10 = Process Access (credential dumping 탐지)
                      11 = File Create
    - computer_name: 특정 호스트만 필터링. 비우면 전체 호스트 대상.
    - limit       : 최대 반환 건수 (기본 50, 최대 500).

    Returns:
    - JSON object with `result`, `filter`, `count`, and `events`.
    """
    if not event_ids:
        return {"result": "error", "message": "event_ids 목록이 비어있습니다."}

    safe_limit = min(max(limit, 1), 500)
    db_path = _resolve_db_path()

    if not db_path.exists():
        return {"result": "error", "message": f"SQLite DB not found: {db_path}"}

    # SQL IN 절을 위한 플레이스홀더 생성
    placeholders = ",".join("?" for _ in event_ids)
    str_ids = [str(eid) for eid in event_ids]

    query = f"""
        SELECT id, event_time, event_id, computer_name, username,
               source_ip, message, detection_json, risk_json
        FROM events
        WHERE event_id IN ({placeholders})
        {"AND computer_name = ?" if computer_name else ""}
        ORDER BY id DESC
        LIMIT ?
    """
    bindings: List[Any] = str_ids
    if computer_name:
        bindings.append(computer_name)
    bindings.append(safe_limit)

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(query, bindings)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return {
            "result": "ok",
            "filter": {"event_ids": event_ids, "computer_name": computer_name or "all"},
            "count": len(rows),
            "events": rows,
        }
    except sqlite3.Error as exc:
        return {"result": "error", "message": f"SQLite query failed: {exc}"}


# ══════════════════════════════════════════════════════════════════════
# BloodHound 정찰 도구
# ══════════════════════════════════════════════════════════════════════
BLOODHOUND_OUTPUT_ROOT = Path(os.getenv("BLOODHOUND_OUTPUT_DIR", "/data/bloodhound"))


@mcp.tool()
def run_bloodhound_collection(
    domain: str,
    username: str,
    password: str,
    domain_controller: str = "",
    nameserver: str = "",
    collection_method: str = "Default",
    use_ldaps: bool = False,
    timeout_seconds: int = 600,
) -> Dict[str, Any]:
    """
    Red Team용: bloodhound-python으로 AD 환경 정보를 수집합니다.

    BloodHound 데이터(사용자, 그룹, 컴퓨터, ACL, 세션, 트러스트 등)를 LDAP로
    수집하여 JSON 파일로 저장합니다. 결과 JSON은 BloodHound CE/Legacy GUI로
    드래그&드롭하면 공격 경로를 시각화할 수 있습니다.

    Inputs:
    - domain            : 대상 도메인 (예: "lab.local")
    - username          : 인증할 사용자명 (도메인 계정, 일반 권한도 가능)
    - password          : 인증 비밀번호
    - domain_controller : DC 호스트명/FQDN. 비우면 도메인에서 자동 탐색.
    - nameserver        : DNS 서버 IP. DC IP를 지정하면 자동 탐색 안정성 ↑
    - collection_method : 수집 범위. 기본 "Default".
                          - "Default"  : 사용자/그룹/컴퓨터/ACL/세션 (가장 일반적)
                          - "All"      : 전체 (시간 가장 오래 걸림)
                          - "Group"    : 그룹 멤버십만
                          - "ACL"      : ACL 정보만
                          - "Trusts"   : 도메인 신뢰 관계
                          - "Session"  : 활성 세션 (NetSessionEnum)
                          - "LoggedOn" : 로그온된 사용자
                          - "ObjectProps", "Container", "DCOnly" 등 지원
    - use_ldaps         : LDAPS(636) 사용 여부 (기본 LDAP 389)
    - timeout_seconds   : 최대 실행 시간 (기본 600초)

    Returns:
    - JSON object with `result`, `output_dir`, `files`, `stdout`, `stderr`.
    - `files`는 생성된 JSON 파일 경로 목록 (BloodHound에 임포트할 파일들).
    """
    if not domain or not username or not password:
        return {"result": "error", "message": "domain, username, password는 필수입니다."}

    # 출력 디렉토리: 실행 시각 기준으로 분리
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace("/", "_").replace("\\", "_")
    out_dir = BLOODHOUND_OUTPUT_ROOT / f"{timestamp}_{safe_domain}"
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd: List[str] = [
        "bloodhound-python",
        "-d", domain,
        "-u", username,
        "-p", password,
        "-c", collection_method,
        "--zip",  # 결과를 zip 하나로 묶어 BloodHound 임포트 편하게
    ]
    if domain_controller:
        cmd.extend(["-dc", domain_controller])
    if nameserver:
        cmd.extend(["-ns", nameserver])
    if use_ldaps:
        cmd.append("--use-ldaps")

    redacted_cmd = " ".join(
        shlex.quote("***" if i > 0 and cmd[i - 1] == "-p" else c)
        for i, c in enumerate(cmd)
    )

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(out_dir),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "result": "error",
            "message": f"bloodhound-python timeout ({timeout_seconds}s)",
            "command": redacted_cmd,
            "output_dir": str(out_dir),
            "stdout": (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            "stderr": (exc.stderr or b"").decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
        }
    except FileNotFoundError:
        return {
            "result": "error",
            "message": "bloodhound-python 실행 파일을 찾을 수 없습니다. 컨테이너 재빌드가 필요합니다.",
        }
    except Exception as exc:
        return {"result": "error", "message": f"실행 실패: {exc}"}

    files = sorted(str(p) for p in out_dir.glob("*"))
    json_files = [f for f in files if f.endswith(".json") or f.endswith(".zip")]

    status = "ok" if proc.returncode == 0 and json_files else "error"
    return {
        "result": status,
        "command": redacted_cmd,
        "return_code": proc.returncode,
        "output_dir": str(out_dir),
        "files": files,
        "json_files": json_files,
        "file_count": len(json_files),
        "stdout_tail": (proc.stdout or "")[-2000:],
        "stderr_tail": (proc.stderr or "")[-2000:],
        "hint": (
            "성공 시 .zip 파일을 BloodHound CE GUI에 드래그&드롭하면 공격 경로를 시각화할 수 있습니다."
            if status == "ok"
            else "stderr_tail을 확인하세요. 흔한 원인: DC 도달 불가 / DNS 미설정 / 자격증명 오류 / Kerberos 시계 차이."
        ),
    }


@mcp.tool()
def list_bloodhound_collections() -> Dict[str, Any]:
    """
    Red Team용: 지금까지 수행한 BloodHound 수집 결과 목록을 반환합니다.

    `run_bloodhound_collection`으로 만든 디렉토리들을 시간순으로 정리해서
    반환합니다. 각 항목의 `files`로 BloodHound에 임포트할 zip/json 경로를 확인할 수 있습니다.
    """
    if not BLOODHOUND_OUTPUT_ROOT.exists():
        return {"result": "ok", "count": 0, "collections": []}

    collections: List[Dict[str, Any]] = []
    for d in sorted(BLOODHOUND_OUTPUT_ROOT.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        files = sorted(str(p) for p in d.glob("*"))
        collections.append(
            {
                "name": d.name,
                "path": str(d),
                "file_count": len(files),
                "files": files,
            }
        )

    return {
        "result": "ok",
        "output_root": str(BLOODHOUND_OUTPUT_ROOT),
        "count": len(collections),
        "collections": collections,
    }


# ══════════════════════════════════════════════════════════════════════
# BloodHound 분석/시각화 도구
# ══════════════════════════════════════════════════════════════════════
def _resolve_collection_dir(collection_name: str) -> Path:
    """collection_name이 빈 값이면 가장 최근 수집 결과 폴더를 반환."""
    if not BLOODHOUND_OUTPUT_ROOT.exists():
        raise FileNotFoundError(f"수집 결과가 없습니다: {BLOODHOUND_OUTPUT_ROOT}")
    if collection_name:
        target = BLOODHOUND_OUTPUT_ROOT / collection_name
        if not target.exists():
            raise FileNotFoundError(f"컬렉션을 찾을 수 없습니다: {target}")
        return target
    dirs = sorted([d for d in BLOODHOUND_OUTPUT_ROOT.iterdir() if d.is_dir()], reverse=True)
    if not dirs:
        raise FileNotFoundError("수집 결과가 없습니다.")
    return dirs[0]


def _load_bloodhound_jsons(coll_dir: Path) -> Dict[str, List[Dict[str, Any]]]:
    """zip을 풀고 JSON을 카테고리별로 로드."""
    import zipfile
    # zip이 있으면 풀기
    for z in coll_dir.glob("*.zip"):
        try:
            with zipfile.ZipFile(z) as zf:
                zf.extractall(coll_dir)
        except Exception:
            pass

    data: Dict[str, List[Dict[str, Any]]] = {
        "users": [], "groups": [], "computers": [],
        "domains": [], "gpos": [], "ous": [], "containers": [],
    }
    for j in coll_dir.glob("*.json"):
        for key in data.keys():
            if j.name.endswith(f"_{key}.json"):
                try:
                    with j.open("r", encoding="utf-8") as f:
                        payload = json.load(f)
                    data[key] = payload.get("data", [])
                except Exception:
                    pass
                break
    return data


def _build_sid_map(data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, str]:
    sid2name: Dict[str, str] = {}
    for arr in data.values():
        for o in arr:
            sid = o.get("ObjectIdentifier")
            if sid:
                sid2name[sid] = o.get("Properties", {}).get("name", sid)
    return sid2name


@mcp.tool()
def analyze_bloodhound_collection(collection_name: str = "") -> Dict[str, Any]:
    """
    Red Team용: BloodHound 수집 결과를 자동 분석하여 핵심 공격 경로를 찾습니다.

    `run_bloodhound_collection` 결과 폴더의 JSON을 파싱해서 Kerberoastable,
    AS-REP roastable, Unconstrained Delegation, 고가치 그룹 멤버십, 위험 ACE 등
    핵심 정보를 추출합니다.

    Inputs:
    - collection_name : 분석할 디렉토리 이름. 비우면 가장 최근 수집을 사용.

    Returns:
    - 도메인 요약, 핵심 공격 경로 카테고리별 리스트.
    """
    try:
        coll = _resolve_collection_dir(collection_name)
    except FileNotFoundError as exc:
        return {"result": "error", "message": str(exc)}

    data = _load_bloodhound_jsons(coll)
    sid2name = _build_sid_map(data)

    # 핵심 추출
    kerberoastable = []
    asreproastable = []
    unconstrained_users = []
    unconstrained_computers = []
    admin_count_users = []
    high_value_groups = {}

    HV_NAMES = {
        "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
        "ADMINISTRATORS", "ACCOUNT OPERATORS", "BACKUP OPERATORS",
        "SERVER OPERATORS", "PRINT OPERATORS", "DNSADMINS",
        "GROUP POLICY CREATOR OWNERS", "DOMAIN CONTROLLERS",
        "REMOTE DESKTOP USERS",
    }

    for u in data["users"]:
        p = u.get("Properties", {})
        spns = p.get("serviceprincipalnames", [])
        if spns and p.get("name", "").upper() != f"KRBTGT@{p.get('domain','')}":
            kerberoastable.append({"name": p.get("name"), "spns": spns, "enabled": p.get("enabled")})
        if p.get("dontreqpreauth"):
            asreproastable.append({"name": p.get("name"), "enabled": p.get("enabled")})
        if p.get("unconstraineddelegation"):
            unconstrained_users.append(p.get("name"))
        if p.get("admincount"):
            admin_count_users.append({"name": p.get("name"), "enabled": p.get("enabled")})

    for c in data["computers"]:
        p = c.get("Properties", {})
        if p.get("unconstraineddelegation"):
            unconstrained_computers.append(p.get("name"))

    for g in data["groups"]:
        name = g.get("Properties", {}).get("name", "")
        short = name.split("@")[0].upper()
        if short in HV_NAMES and g.get("Members"):
            members = []
            for m in g["Members"]:
                members.append({
                    "type": m.get("ObjectType"),
                    "name": sid2name.get(m.get("ObjectIdentifier"), m.get("ObjectIdentifier")),
                })
            high_value_groups[name] = members

    domain_info = {}
    if data["domains"]:
        dp = data["domains"][0].get("Properties", {})
        domain_info = {
            "name": dp.get("name"),
            "functional_level": dp.get("functionallevel"),
        }

    # Kerberoastable 중 Domain Admin 멤버 → CRITICAL 경고
    da_names = {m["name"] for m in high_value_groups.get(f"DOMAIN ADMINS@{domain_info.get('name','')}", [])}
    da_names |= {m["name"] for m in high_value_groups.get("DOMAIN ADMINS", [])}
    for k in kerberoastable:
        k["is_domain_admin"] = k["name"] in da_names

    return {
        "result": "ok",
        "collection": coll.name,
        "domain": domain_info,
        "stats": {
            "users": len(data["users"]),
            "groups": len(data["groups"]),
            "computers": len(data["computers"]),
            "gpos": len(data["gpos"]),
            "ous": len(data["ous"]),
        },
        "kerberoastable": kerberoastable,
        "asreproastable": asreproastable,
        "unconstrained_delegation": {
            "users": unconstrained_users,
            "computers": unconstrained_computers,
        },
        "admin_count_users": admin_count_users,
        "high_value_groups": high_value_groups,
    }


@mcp.tool()
def generate_bloodhound_mermaid(
    collection_name: str = "",
    diagram_type: str = "attack_paths",
) -> Dict[str, Any]:
    """
    Red Team용: BloodHound 분석 결과를 Mermaid 다이어그램으로 변환합니다.

    Mermaid는 Claude/대시보드에서 바로 렌더링되는 텍스트 기반 다이어그램입니다.

    Inputs:
    - collection_name : 분석할 컬렉션. 비우면 최신.
    - diagram_type    :
        * "attack_paths" : 공격 경로 요약 (kerberoastable/asrep/dnsadmins → DA 경로)
        * "group_tree"   : 고가치 그룹 멤버십 트리
        * "user_groups"  : 사용자별 가입 그룹

    Returns:
    - mermaid : ```mermaid 코드 블록 (그대로 출력하면 렌더됨)
    """
    try:
        coll = _resolve_collection_dir(collection_name)
    except FileNotFoundError as exc:
        return {"result": "error", "message": str(exc)}

    data = _load_bloodhound_jsons(coll)
    sid2name = _build_sid_map(data)

    def safe_id(s: str) -> str:
        return "n_" + "".join(c if c.isalnum() else "_" for c in s)[:60]

    def short_label(s: str) -> str:
        return s.split("@")[0]

    lines: List[str] = ["graph LR"]

    if diagram_type == "attack_paths":
        # 도메인 노드
        domain_name = data["domains"][0].get("Properties", {}).get("name", "DOMAIN") if data["domains"] else "DOMAIN"
        domain_id = safe_id(domain_name)
        lines.append(f'    {domain_id}["🏢 {short_label(domain_name)}"]:::domain')

        # Domain Admins 노드
        da_id = safe_id("DA")
        lines.append(f'    {da_id}["👑 Domain Admins"]:::da')
        lines.append(f'    {da_id} --> {domain_id}')

        # Kerberoastable
        for u in data["users"]:
            p = u.get("Properties", {})
            spns = p.get("serviceprincipalnames", [])
            name = p.get("name", "")
            if spns and "KRBTGT" not in name.upper():
                uid = safe_id(name)
                label = short_label(name)
                lines.append(f'    {uid}["🎯 {label}<br/>(SPN)"]:::kerb')

        # AS-REP roastable
        for u in data["users"]:
            p = u.get("Properties", {})
            if p.get("dontreqpreauth"):
                name = p.get("name", "")
                uid = safe_id(name)
                label = short_label(name)
                lines.append(f'    {uid}["🔓 {label}<br/>(AS-REP)"]:::asrep')

        # DnsAdmins → DC
        dc_id = safe_id("DC")
        lines.append(f'    {dc_id}["🖥️ DC (SYSTEM)"]:::dc')
        lines.append(f'    {dc_id} -->|hosts| {domain_id}')

        for g in data["groups"]:
            name = g.get("Properties", {}).get("name", "")
            if "DNSADMINS" in name.upper():
                dns_id = safe_id("DNSADMINS")
                lines.append(f'    {dns_id}["⚙️ DnsAdmins"]:::dns')
                lines.append(f'    {dns_id} -->|DLL Inject| {dc_id}')
                for m in g.get("Members", []):
                    mname = sid2name.get(m.get("ObjectIdentifier"), "?")
                    mid = safe_id(mname)
                    lines.append(f'    {mid}["👤 {short_label(mname)}"]:::user')
                    lines.append(f'    {mid} -->|MemberOf| {dns_id}')

        # Domain Admins 멤버
        for g in data["groups"]:
            name = g.get("Properties", {}).get("name", "")
            if "DOMAIN ADMINS" in name.upper():
                for m in g.get("Members", []):
                    mname = sid2name.get(m.get("ObjectIdentifier"), "?")
                    mid = safe_id(mname)
                    if m.get("ObjectType") == "User":
                        lines.append(f'    {mid}["👑 {short_label(mname)}"]:::admin')
                        lines.append(f'    {mid} -->|MemberOf| {da_id}')

                        # 만약 이 admin이 kerberoastable이면 critical edge
                        for u in data["users"]:
                            up = u.get("Properties", {})
                            if up.get("name") == mname and up.get("serviceprincipalnames"):
                                lines.append(f'    {mid}:::critical')

        lines.extend([
            "    classDef domain fill:#1f2937,stroke:#fbbf24,color:#fff,stroke-width:2px",
            "    classDef da fill:#7c2d12,stroke:#fbbf24,color:#fff",
            "    classDef admin fill:#dc2626,stroke:#fff,color:#fff",
            "    classDef critical fill:#991b1b,stroke:#fbbf24,color:#fff,stroke-width:4px",
            "    classDef kerb fill:#ea580c,stroke:#fff,color:#fff",
            "    classDef asrep fill:#d97706,stroke:#fff,color:#fff",
            "    classDef dns fill:#7c3aed,stroke:#fff,color:#fff",
            "    classDef dc fill:#0369a1,stroke:#fff,color:#fff",
            "    classDef user fill:#374151,stroke:#9ca3af,color:#fff",
        ])

    elif diagram_type == "group_tree":
        HV = ["DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS",
              "SCHEMA ADMINS", "DNSADMINS", "ACCOUNT OPERATORS",
              "BACKUP OPERATORS", "SERVER OPERATORS"]
        for g in data["groups"]:
            name = g.get("Properties", {}).get("name", "")
            short = name.split("@")[0].upper()
            if short in HV and g.get("Members"):
                gid = safe_id(name)
                lines.append(f'    {gid}[("👥 {short_label(name)}")]')
                for m in g.get("Members", []):
                    mname = sid2name.get(m.get("ObjectIdentifier"), "?")
                    mid = safe_id(mname + "_" + name)  # avoid duplicate
                    icon = "👤" if m.get("ObjectType") == "User" else "👥"
                    lines.append(f'    {mid}["{icon} {short_label(mname)}"]')
                    lines.append(f'    {mid} --> {gid}')

    elif diagram_type == "user_groups":
        # 사용자 → 가입 그룹 매핑
        user_groups: Dict[str, List[str]] = {}
        for g in data["groups"]:
            gname = g.get("Properties", {}).get("name", "")
            for m in g.get("Members", []):
                if m.get("ObjectType") == "User":
                    uname = sid2name.get(m.get("ObjectIdentifier"), "?")
                    user_groups.setdefault(uname, []).append(gname)

        for uname, gnames in user_groups.items():
            uid = safe_id(uname)
            lines.append(f'    {uid}["👤 {short_label(uname)}"]')
            for gname in gnames:
                gid = safe_id(gname)
                lines.append(f'    {uid} --> {gid}["👥 {short_label(gname)}"]')

    else:
        return {"result": "error", "message": f"unknown diagram_type: {diagram_type}"}

    mermaid_code = "\n".join(lines)
    return {
        "result": "ok",
        "collection": coll.name,
        "diagram_type": diagram_type,
        "mermaid": f"```mermaid\n{mermaid_code}\n```",
        "raw": mermaid_code,
    }


@mcp.tool()
def generate_bloodhound_html(collection_name: str = "") -> Dict[str, Any]:
    """
    Red Team용: BloodHound 분석 결과를 인터랙티브 HTML 그래프로 저장합니다.

    vis-network.js 기반 단일 HTML 파일을 생성합니다. 노드를 드래그/줌/검색 가능하며
    오프라인에서도 동작합니다 (CDN 의존). 파일을 브라우저로 열면 됩니다.

    Inputs:
    - collection_name : 분석할 컬렉션. 비우면 최신.

    Returns:
    - html_path : 생성된 HTML 파일 경로
    """
    try:
        coll = _resolve_collection_dir(collection_name)
    except FileNotFoundError as exc:
        return {"result": "error", "message": str(exc)}

    data = _load_bloodhound_jsons(coll)
    sid2name = _build_sid_map(data)

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen: set = set()

    def add_node(nid: str, label: str, group: str, title: str = ""):
        if nid in seen:
            return
        seen.add(nid)
        nodes.append({"id": nid, "label": label, "group": group, "title": title or label})

    # 사용자 노드
    for u in data["users"]:
        p = u.get("Properties", {})
        sid = u["ObjectIdentifier"]
        name = p.get("name", sid)
        flags = []
        if p.get("serviceprincipalnames"): flags.append("Kerberoastable")
        if p.get("dontreqpreauth"): flags.append("AS-REP roastable")
        if p.get("admincount"): flags.append("AdminCount")
        if p.get("unconstraineddelegation"): flags.append("Unconstrained")

        group = "user"
        if "Kerberoastable" in flags: group = "kerberoastable"
        if "AS-REP roastable" in flags: group = "asrep"
        if p.get("admincount"): group = "admin"

        title = f"{name}\\n" + " | ".join(flags) if flags else name
        add_node(sid, name.split("@")[0], group, title)

    # 그룹 노드 (고가치만)
    HV = {"DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS",
          "SCHEMA ADMINS", "DNSADMINS", "ACCOUNT OPERATORS",
          "BACKUP OPERATORS", "SERVER OPERATORS",
          "GROUP POLICY CREATOR OWNERS", "REMOTE DESKTOP USERS"}
    for g in data["groups"]:
        gp = g.get("Properties", {})
        gname = gp.get("name", "")
        if gname.split("@")[0].upper() not in HV:
            continue
        gsid = g["ObjectIdentifier"]
        add_node(gsid, gname.split("@")[0], "group_hv", gname)
        for m in g.get("Members", []):
            msid = m.get("ObjectIdentifier")
            if msid in seen:
                edges.append({"from": msid, "to": gsid, "label": "MemberOf"})

    # 컴퓨터 노드
    for c in data["computers"]:
        cp = c.get("Properties", {})
        csid = c["ObjectIdentifier"]
        name = cp.get("name", csid)
        flags = []
        if cp.get("unconstraineddelegation"): flags.append("Unconstrained")
        group = "dc" if "DC" in name.upper() else "computer"
        add_node(csid, name.split(".")[0], group, name + ("\\n" + ", ".join(flags) if flags else ""))

    out_path = coll / "graph.html"
    html = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>BloodHound Graph - %s</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
body{margin:0;font-family:-apple-system,sans-serif;background:#111;color:#eee}
#info{padding:10px;background:#1f2937;border-bottom:1px solid #374151}
#info h2{margin:0 0 8px 0;color:#fbbf24}
#legend{font-size:12px;display:flex;gap:12px;flex-wrap:wrap}
#legend span{padding:2px 8px;border-radius:4px;color:#fff}
#net{width:100vw;height:calc(100vh - 80px)}
.l-admin{background:#dc2626}
.l-kerb{background:#ea580c}
.l-asrep{background:#d97706}
.l-user{background:#374151}
.l-group{background:#7c3aed}
.l-dc{background:#0369a1}
.l-comp{background:#1f2937;border:1px solid #4b5563}
</style></head>
<body>
<div id="info">
<h2>🛡️ BloodHound Attack Graph: %s</h2>
<div id="legend">
<span class="l-admin">👑 Admin</span>
<span class="l-kerb">🎯 Kerberoastable</span>
<span class="l-asrep">🔓 AS-REP roastable</span>
<span class="l-user">👤 User</span>
<span class="l-group">👥 High-Value Group</span>
<span class="l-dc">🖥️ Domain Controller</span>
<span class="l-comp">💻 Computer</span>
</div>
</div>
<div id="net"></div>
<script>
const nodes = new vis.DataSet(%s);
const edges = new vis.DataSet(%s);
const network = new vis.Network(document.getElementById('net'), {nodes, edges}, {
  physics: {stabilization: true, barnesHut: {gravitationalConstant: -8000, springLength: 150}},
  groups: {
    admin: {color:{background:'#dc2626',border:'#fbbf24'}, shape:'star'},
    kerberoastable: {color:{background:'#ea580c',border:'#fff'}, shape:'diamond'},
    asrep: {color:{background:'#d97706',border:'#fff'}, shape:'diamond'},
    user: {color:{background:'#374151',border:'#9ca3af'}, shape:'dot'},
    group_hv: {color:{background:'#7c3aed',border:'#fbbf24'}, shape:'hexagon'},
    dc: {color:{background:'#0369a1',border:'#fbbf24'}, shape:'box'},
    computer: {color:{background:'#1f2937',border:'#4b5563'}, shape:'box'}
  },
  nodes:{font:{color:'#fff',size:14}},
  edges:{color:{color:'#6b7280'},arrows:'to',font:{color:'#9ca3af',size:10}}
});
</script>
</body></html>""" % (
        coll.name,
        coll.name,
        json.dumps(nodes, ensure_ascii=False),
        json.dumps(edges, ensure_ascii=False),
    )

    out_path.write_text(html, encoding="utf-8")

    return {
        "result": "ok",
        "collection": coll.name,
        "html_path": str(out_path),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "hint": f"호스트에서 브라우저로 열기: 파일 경로를 file:// 로 접근하거나 'open {out_path}' (mac), 'start {out_path}' (Windows) 실행",
    }


# ══════════════════════════════════════════════════════════════════════
# Powerview 정찰 도구
# ══════════════════════════════════════════════════════════════════════
@mcp.tool()
def run_powerview_recon(
    target_ip: str = "",
    requested_by: str = "",
    winrm_user: str = "",
    winrm_pass: str = "",
    domain_name: str = "lab.local",
    scenario_id: str = "powerview_AD_recon",
) -> Dict[str, Any]:
    """
    Red Team용: PowerView 기반 AD 정찰 시나리오를 실행합니다.

    이 도구는 직접 PowerView를 실행하지 않고 backend /scenario/run을 통해
    Attack Runner의 PowerView 시나리오를 실행합니다.
    실행 결과는 시나리오 스크립트가 backend /recon-results에 저장해야 하며,
    저장된 최신 결과는 dashboard 정찰 탭의 PowerView 섹션에서 확인합니다.

    Inputs:
    - target_ip    : PowerView를 실행할 Windows 호스트 IP.
                     비우면 VICTIM_URL 환경변수를 사용합니다.
    - requested_by : 실행자. 비우면 ATTACK_REQUESTED_BY 환경변수를 사용합니다.
    - winrm_user   : WinRM 접속 사용자.
    - winrm_pass   : WinRM 접속 비밀번호.
    - domain_name  : 평가 대상 도메인. 기본 lab.local.
    - scenario_id  : Attack Runner의 PowerView 시나리오 ID. 기본 powerview.
    """
    final_target_ip = target_ip or DEFAULT_TARGET_IP
    final_requested_by = requested_by or DEFAULT_REQUESTED_BY

    if not final_target_ip:
        return {"result": "error", "message": "target_ip가 필요합니다. VICTIM_URL도 비어 있습니다."}
    if not final_requested_by:
        return {"result": "error", "message": "requested_by가 필요합니다. ATTACK_REQUESTED_BY도 비어 있습니다."}
    if not winrm_user:
        return {"result": "error", "message": "winrm_user는 필수입니다."}
    if not winrm_pass:
        return {"result": "error", "message": "winrm_pass는 필수입니다."}

    params = {
        "target_ip": final_target_ip,
        "requested_by": final_requested_by,
        "domain_name": domain_name,
    }

    if winrm_user:
        params["winrm_user"] = winrm_user
    if winrm_pass:
        params["winrm_pass"] = winrm_pass

    return _run_scenario_via_backend(scenario_id=scenario_id, params=params)


# ══════════════════════════════════════════════════════════════════════
# PingCastle 정찰 도구
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
def run_pingcastle_healthcheck(
    target_ip: str = "",
    requested_by: str = "",
    winrm_user: str = "lab_admin",
    winrm_pass: str = "",
    domain_name: str = "lab.local",
    scenario_id: str = "pingcastle_AD_recon",
) -> Dict[str, Any]:
    """
    Red Team용: PingCastle AD HealthCheck 시나리오를 실행합니다.

    이 도구는 직접 PingCastle를 실행하지 않고 backend /scenario/run을 통해
    Attack Runner의 pingcastle.sh를 실행합니다.

    전제 조건:
    - target_ip Windows 호스트에 C:\\Tools\\PingCastle\\PingCastle.exe가 존재해야 합니다.
    - 해당 호스트에서 lab.local/DC/DNS 접근이 가능해야 합니다.
    - winrm_user/winrm_pass로 target_ip에 WinRM 접속이 가능해야 합니다.
    - pingcastle.sh가 생성한 HTML/XML을 backend /recon-results에 업로드해야
      dashboard 정찰 탭에서 미리보기할 수 있습니다.

    Inputs:
    - target_ip    : PingCastle를 실행할 Windows 호스트 IP. DC 또는 도메인 조인 victim 가능.
    - requested_by : 실행자. 비우면 ATTACK_REQUESTED_BY 환경변수를 사용.
    - winrm_user   : WinRM 접속 사용자. 기본 lab_admin.
    - winrm_pass   : WinRM 접속 비밀번호.
    - domain_name  : 평가 대상 AD 도메인. 기본 lab.local.
    - scenario_id  : Attack Runner의 PingCastle 시나리오 ID. 기본 pingcastle.
    """
    final_target_ip = target_ip or DEFAULT_TARGET_IP
    final_requested_by = requested_by or DEFAULT_REQUESTED_BY

    if not final_target_ip:
        return {"result": "error", "message": "target_ip가 필요합니다. VICTIM_URL도 비어 있습니다."}
    if not final_requested_by:
        return {"result": "error", "message": "requested_by가 필요합니다. ATTACK_REQUESTED_BY도 비어 있습니다."}
    if not winrm_pass:
        return {"result": "error", "message": "winrm_pass는 필수입니다."}

    params = {
        "target_ip": final_target_ip,
        "requested_by": final_requested_by,
        "winrm_user": winrm_user,
        "winrm_pass": winrm_pass,
        "domain_name": domain_name,
    }

    return _run_scenario_via_backend(scenario_id=scenario_id, params=params)


# ══════════════════════════════════════════════════════════════════════
# 통합 정찰 워크플로우
# ══════════════════════════════════════════════════════════════════════

@mcp.tool()
def run_full_recon_workflow(
    target_ip: str = "",
    requested_by: str = "",
    winrm_user: str = "lab_admin",
    winrm_pass: str = "",
    domain_name: str = "lab.local",
    bloodhound_username: str = "",
    bloodhound_password: str = "",
    domain_controller: str = "",
    nameserver: str = "",
    bloodhound_collection_method: str = "Default",
    use_ldaps: bool = False,
    run_powerview: bool = True,
    run_pingcastle: bool = True,
    run_bloodhound: bool = True,
) -> Dict[str, Any]:
    """
    Red Team용: PowerView, PingCastle, BloodHound 정찰을 순서대로 실행합니다.

    이 도구는 대시보드 리포트 생성을 위한 사전 정찰 워크플로우입니다.
    PowerView/PingCastle은 backend /scenario/run을 통해 Attack Runner 시나리오로 실행하고,
    BloodHound는 bloodhound-python 수집 후 분석 및 HTML 그래프 생성을 시도합니다.

    Inputs:
    - target_ip    : PowerView/PingCastle을 실행할 Windows 호스트 IP. 비우면 VICTIM_URL 사용.
    - requested_by : 실행자. 비우면 ATTACK_REQUESTED_BY 사용.
    - winrm_user   : WinRM 접속 사용자.
    - winrm_pass   : WinRM 접속 비밀번호.
    - domain_name  : AD 도메인. 기본 lab.local.
    - bloodhound_username : BloodHound LDAP 수집용 도메인 계정.
    - bloodhound_password : BloodHound LDAP 수집용 비밀번호.
    - domain_controller   : DC 호스트명/FQDN 또는 IP. 선택.
    - nameserver          : DNS 서버 IP. 보통 DC IP. 선택.
    - bloodhound_collection_method : BloodHound 수집 범위. 기본 Default.
    - use_ldaps           : LDAPS 사용 여부.
    - run_powerview       : PowerView 실행 여부.
    - run_pingcastle      : PingCastle 실행 여부.
    - run_bloodhound      : BloodHound 실행 여부.

    Returns:
    - 각 단계별 실행 결과와 전체 성공/실패 요약.
    """
    final_target_ip = target_ip or DEFAULT_TARGET_IP
    final_requested_by = requested_by or DEFAULT_REQUESTED_BY

    steps: Dict[str, Any] = {}

    # 공통 필수값 체크
    if (run_powerview or run_pingcastle) and not final_target_ip:
        return {
            "result": "error",
            "message": "target_ip가 필요합니다. VICTIM_URL도 비어 있습니다.",
        }

    if (run_powerview or run_pingcastle) and not final_requested_by:
        return {
            "result": "error",
            "message": "requested_by가 필요합니다. ATTACK_REQUESTED_BY도 비어 있습니다.",
        }

    if (run_powerview or run_pingcastle) and not winrm_pass:
        return {
            "result": "error",
            "message": "winrm_pass는 PowerView/PingCastle 실행에 필요합니다.",
        }

    if run_bloodhound and (not bloodhound_username or not bloodhound_password):
        return {
            "result": "error",
            "message": "BloodHound 실행에는 bloodhound_username, bloodhound_password가 필요합니다.",
        }

    # 1. PowerView
    if run_powerview:
        try:
            steps["powerview"] = run_powerview_recon(
                target_ip=final_target_ip,
                requested_by=final_requested_by,
                winrm_user=winrm_user,
                winrm_pass=winrm_pass,
                domain_name=domain_name,
            )
        except Exception as exc:
            steps["powerview"] = {
                "result": "error",
                "message": f"PowerView 실행 중 예외 발생: {exc}",
            }
    else:
        steps["powerview"] = {
            "result": "skipped",
            "message": "run_powerview=False",
        }

    # 2. PingCastle
    if run_pingcastle:
        try:
            steps["pingcastle"] = run_pingcastle_healthcheck(
                target_ip=final_target_ip,
                requested_by=final_requested_by,
                winrm_user=winrm_user,
                winrm_pass=winrm_pass,
                domain_name=domain_name,
            )
        except Exception as exc:
            steps["pingcastle"] = {
                "result": "error",
                "message": f"PingCastle 실행 중 예외 발생: {exc}",
            }
    else:
        steps["pingcastle"] = {
            "result": "skipped",
            "message": "run_pingcastle=False",
        }

    # 3. BloodHound 수집 + 분석 + HTML 생성
    if run_bloodhound:
        try:
            bh_collect = run_bloodhound_collection(
                domain=domain_name,
                username=bloodhound_username,
                password=bloodhound_password,
                domain_controller=domain_controller,
                nameserver=nameserver,
                collection_method=bloodhound_collection_method,
                use_ldaps=use_ldaps,
            )
            steps["bloodhound_collection"] = bh_collect

            if bh_collect.get("result") == "ok":
                # 방금 생성된 output_dir의 폴더명을 collection_name으로 사용
                output_dir = bh_collect.get("output_dir", "")
                collection_name = os.path.basename(output_dir) if output_dir else ""

                try:
                    steps["bloodhound_analysis"] = analyze_bloodhound_collection(
                        collection_name=collection_name
                    )
                except Exception as exc:
                    steps["bloodhound_analysis"] = {
                        "result": "error",
                        "message": f"BloodHound 분석 중 예외 발생: {exc}",
                    }

                try:
                    steps["bloodhound_html"] = generate_bloodhound_html(
                        collection_name=collection_name
                    )
                except Exception as exc:
                    steps["bloodhound_html"] = {
                        "result": "error",
                        "message": f"BloodHound HTML 생성 중 예외 발생: {exc}",
                    }
            else:
                steps["bloodhound_analysis"] = {
                    "result": "skipped",
                    "message": "BloodHound 수집 실패로 분석 생략",
                }
                steps["bloodhound_html"] = {
                    "result": "skipped",
                    "message": "BloodHound 수집 실패로 HTML 생성 생략",
                }

        except Exception as exc:
            steps["bloodhound_collection"] = {
                "result": "error",
                "message": f"BloodHound 실행 중 예외 발생: {exc}",
            }
    else:
        steps["bloodhound_collection"] = {
            "result": "skipped",
            "message": "run_bloodhound=False",
        }

    # 전체 상태 계산
    failed_steps = []
    skipped_steps = []

    for name, payload in steps.items():
        status = payload.get("result") if isinstance(payload, dict) else None
        if status == "error":
            failed_steps.append(name)
        elif status == "skipped":
            skipped_steps.append(name)

    overall_result = "ok" if not failed_steps else "partial_error"

    return {
        "result": overall_result,
        "message": (
            "통합 정찰 워크플로우가 완료되었습니다."
            if overall_result == "ok"
            else "일부 정찰 단계에서 오류가 발생했습니다."
        ),
        "target_ip": final_target_ip,
        "requested_by": final_requested_by,
        "domain_name": domain_name,
        "failed_steps": failed_steps,
        "skipped_steps": skipped_steps,
        "steps": steps,
        "next_action": (
            "대시보드의 정찰 탭 또는 리포트 탭에서 최신 결과를 확인하세요. "
            "PowerView/PingCastle은 시나리오가 비동기 실행될 수 있으므로 완료 후 새로고침이 필요할 수 있습니다."
        ),
    }


if __name__ == "__main__":
    # MCP_TRANSPORT 환경변수로 전송 방식 선택
    #   - "http"  : streamable-http (대시보드 통합 / 팀 공용 배포 모드)
    #   - "sse"   : SSE (구버전 호환)
    #   - "stdio" : 로컬 stdio (기본값, Claude Desktop/CLI 직결)
    transport = os.getenv("MCP_TRANSPORT", "stdio").lower()
    if transport == "http":
        mcp.run(transport="streamable-http")
    elif transport == "sse":
        mcp.run(transport="sse")
    else:
        mcp.run()