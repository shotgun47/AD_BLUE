# AI Chat & MCP 도구 가이드

## 전체 구조

```
사용자 (브라우저)
    ↓ 자연어 입력
대시보드 AI Chat (Streamlit)
    ↓ LiteLLM (Claude / Gemini)
    ↓ tool_use 응답 시
MCP 서버 (adlab-mcp 컨테이너 :9000)
    ↓ 도구 실행
Backend API / SQLite DB / Attack Runner
```

---

## 1. AI Chat 사용법

접속: **http://localhost:8501/AI_Chat**

### 모델 선택

사이드바에서 LLM을 선택합니다.

| 모델 | 설명 | API 키 |
|------|------|--------|
| ⚡ Gemini Flash (최신) | 빠름, 무료 티어 | `GEMINI_API_KEY` |
| ⚡ Gemini 2.5 Flash | 안정 버전 | `GEMINI_API_KEY` |
| ⚡ Gemini 2.0 Flash | 이전 안정 버전 | `GEMINI_API_KEY` |
| 🔵 Gemini 2.5 Pro | 고성능 | `GEMINI_API_KEY` |
| 🟠 Claude Haiku 4.5 | 빠름 | `ANTHROPIC_API_KEY` |
| 🟡 Claude Sonnet 4.5 | 균형 | `ANTHROPIC_API_KEY` |

`.env` 파일에 사용할 모델의 API 키를 등록해야 합니다.

```env
ANTHROPIC_API_KEY=sk-ant-...
GEMINI_API_KEY=AIza...
```

### 주요 명령 예시

```
# 보안 로그 조회
최근 보안 로그 50건 보여줘
이벤트 ID 4625 로그만 필터링해줘

# 공격 시나리오
사용 가능한 공격 시나리오 목록 보여줘
AS-REP Roasting 공격 실행해줘

# BloodHound
BloodHound 수집 실행해줘 (도메인: lab.local, 계정: victim1, 비밀번호: xxx)
최근 BloodHound 수집 결과 분석해줘
BloodHound HTML 그래프 생성해줘

# 랩 설정 확인
현재 랩 설정 확인해줘
```

### 동작 방식

1. 사용자가 자연어로 입력
2. AI가 적절한 MCP 도구를 선택해 자동 호출
3. 도구 실행 결과를 받아 한국어로 요약 응답
4. 공격 실행 전에는 반드시 파라미터를 확인하고 사용자에게 승인 요청

---

## 2. 현재 MCP 도구 목록

`mcp/ad_mcp_server.py` 에 정의되어 있습니다.

| 도구명 | 역할 | 주요 파라미터 |
|--------|------|--------------|
| `get_recent_security_logs` | 최근 보안 이벤트 조회 | `limit` |
| `get_lab_config` | 랩 설정 조회 (target_ip, requested_by 기본값) | - |
| `list_attack_scenarios` | 공격 시나리오 목록 조회 | - |
| `execute_attack_scenario` | 공격 시나리오 실행 | `scenario_id`, `params` |
| `filter_sysmon_events` | Sysmon 이벤트 ID 필터링 | `event_ids`, `computer_name`, `limit` |
| `run_bloodhound_collection` | BloodHound 데이터 수집 | `domain`, `username`, `password` |
| `list_bloodhound_collections` | BloodHound 수집 결과 목록 | - |
| `analyze_bloodhound_collection` | BloodHound 분석 (공격 경로 추출) | `collection_name` |
| `generate_bloodhound_mermaid` | Mermaid 다이어그램 생성 | `collection_name`, `diagram_type` |
| `generate_bloodhound_html` | 인터랙티브 HTML 그래프 생성 | `collection_name` |

### 파라미터 자동 주입

AI Chat은 아래 환경변수를 자동으로 파라미터로 활용합니다.

| 환경변수 | 용도 |
|----------|------|
| `VICTIM_URL` | `target_ip` 기본값 |
| `ATTACK_REQUESTED_BY` | `requested_by` 기본값 |

---

## 3. MCP 도구 추가 방법

### 3-1. 파일 위치

```
mcp/ad_mcp_server.py   ← 도구 함수 추가
```

### 3-2. 기본 템플릿

```python
@mcp.tool()
def my_tool(
    param1: str,
    param2: int = 10,
) -> Dict[str, Any]:
    """
    [Blue/Red] Team용: 한 줄 요약.

    Use this tool when ... (AI가 언제 이 도구를 쓸지 판단하는 기준).

    Inputs:
    - param1: 설명
    - param2: 설명 (기본값 10)

    Returns:
    - result: "ok" 또는 "error"
    - data: 반환 데이터
    """
    if not param1:
        return {"result": "error", "message": "param1은 필수입니다."}

    # 구현
    return {"result": "ok", "data": "..."}
```

### 3-3. 규칙

| 항목 | 규칙 |
|------|------|
| 데코레이터 | `@mcp.tool()` 필수 |
| 타입 힌트 | 모든 파라미터에 필수 (`str`, `int`, `bool`, `List[...]`, `Dict[...]`) |
| 반환 타입 | 항상 `Dict[str, Any]` |
| 성공 응답 | `{"result": "ok", ...}` |
| 실패 응답 | `{"result": "error", "message": "이유"}` |
| Docstring | 첫 줄 `[역할]용: 요약` 형식 — AI가 도구 선택 시 가장 먼저 읽음 |

### 3-4. 자주 쓰는 패턴

**SQLite 조회**
```python
db_path = _resolve_db_path()
conn = sqlite3.connect(str(db_path))
conn.row_factory = sqlite3.Row
cur = conn.cursor()
cur.execute("SELECT ... FROM events LIMIT ?", (limit,))
rows = [dict(r) for r in cur.fetchall()]
conn.close()
```

**Backend API 호출**
```python
res = requests.get(f"{BACKEND_URL}/your-endpoint", timeout=10)
res.raise_for_status()
return {"result": "ok", "data": res.json()}
```

**Attack Runner 직접 호출**
```python
res = requests.post(
    f"{ATTACK_RUNNER_URL}/run-scenario",
    json={"scenario_id": "...", "params": {...}},
    headers=_auth_headers(),
    timeout=15,
)
```

### 3-5. 도구 예시

**탐지된 이벤트만 조회**
```python
@mcp.tool()
def get_detected_events(severity: str = "", limit: int = 30) -> Dict[str, Any]:
    """
    Blue Team용: 룰에 탐지된 이벤트만 조회합니다.

    Use this tool to focus on events that triggered detection rules,
    optionally filtered by severity (low / medium / high / critical).

    Inputs:
    - severity: 심각도 필터 ("low", "medium", "high", "critical"). 비우면 전체.
    - limit   : 최대 반환 건수 (기본 30).

    Returns:
    - result, count, events
    """
    db_path = _resolve_db_path()
    if not db_path.exists():
        return {"result": "error", "message": f"DB not found: {db_path}"}

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    if severity:
        cur.execute(
            """
            SELECT id, event_time, event_id, computer_name, username,
                   message, detection_json, risk_json
            FROM events
            WHERE json_extract(detection_json, '$.detection.detected') = 1
              AND json_extract(risk_json, '$.risk.severity') = ?
            ORDER BY id DESC LIMIT ?
            """,
            (severity, min(limit, 500)),
        )
    else:
        cur.execute(
            """
            SELECT id, event_time, event_id, computer_name, username,
                   message, detection_json, risk_json
            FROM events
            WHERE json_extract(detection_json, '$.detection.detected') = 1
            ORDER BY id DESC LIMIT ?
            """,
            (min(limit, 500),),
        )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"result": "ok", "count": len(rows), "events": rows}
```

**BloodHound Neo4j Cypher 조회**
```python
@mcp.tool()
def query_bloodhound(cypher: str) -> Dict[str, Any]:
    """
    Red Team용: BloodHound Neo4j에 Cypher 쿼리를 실행합니다.

    Use this tool to find attack paths, shortest paths to Domain Admin,
    or high-value targets using BloodHound graph data.

    Inputs:
    - cypher: 실행할 Cypher 쿼리 문자열.

    Returns:
    - result, count, rows
    """
    from neo4j import GraphDatabase  # pip install neo4j → requirements.txt에 추가
    NEO4J_URI  = os.getenv("NEO4J_URI",  "bolt://localhost:7687")
    NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASS = os.getenv("NEO4J_PASS", "password")
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        with driver.session() as session:
            rows = [dict(r) for r in session.run(cypher)]
        driver.close()
        return {"result": "ok", "count": len(rows), "rows": rows}
    except Exception as exc:
        return {"result": "error", "message": str(exc)}
```

### 3-6. 적용 방법

도구 추가 후 MCP 컨테이너만 재시작하면 됩니다.

```bash
docker compose up -d --build mcp
```

AI Chat 사이드바에서 **"🔄 도구 다시 불러오기"** 클릭하면 새 도구가 반영됩니다.

---

## 4. Claude Code CLI에서 MCP 연결

대시보드 AI Chat 외에 **Claude Code CLI**에서도 동일한 MCP 도구를 사용할 수 있습니다.

### 4-1. 프로젝트 자동 연결 (.mcp.json)

`C:\AD\.mcp.json` 이 이미 설정되어 있어 해당 디렉토리에서 Claude Code를 실행하면 자동 연결됩니다.

```json
{
  "mcpServers": {
    "ad-lab-agent": {
      "type": "http",
      "url": "http://localhost:9000/mcp"
    }
  }
}
```

### 4-2. 팀원 원격 연결 (Tailscale)

팀원 PC에서 한 번만 실행합니다.

```bash
claude mcp add --transport http ad-lab-agent http://<운영자_Tailscale_IP>:9000/mcp
```

연결 확인:
```bash
claude mcp list
```

> Claude Code를 재시작하면 `ad-lab-agent` 도구가 자동으로 로드됩니다.

---

## 5. Git에 올려야 할 파일

### 올려야 하는 파일

```
# MCP 서버
mcp/ad_mcp_server.py
mcp/Dockerfile
mcp/requirements.txt

# 대시보드
dashboard/pages/AI_Chat.py
dashboard/pages/BloodHound.py
dashboard/requirements.txt
dashboard/Dockerfile
dashboard/app.py

# 백엔드
backend/app/services/scenario_service.py

# 환경 설정
docker-compose.yml
.env.example          ← API 키 없는 예시 파일
.mcp.json             ← Claude Code MCP 연결 설정

# 문서
docs/
```

### 올리면 안 되는 파일

```
.env                  ← API 키, 토큰 포함 (gitignore 처리됨)
data/events.db        ← 런타임 DB
data/bloodhound/      ← 수집 결과 (생성 데이터)
```

### .env.example 최신화

`.env.example`에 새로 추가한 환경변수가 있으면 함께 업데이트합니다.

```env
ATTACK_RUNNER_URL=http://<공격머신 tailnet IP>:9000
ATTACK_RUNNER_TOKEN=lab-secret-token
ATTACK_REQUESTED_BY=<실행자>
VICTIM_URL=<victim tailnet IP>
DB_PATH=/data/events.db
ANTHROPIC_API_KEY=<Claude API 키>
ANTHROPIC_MODEL=claude-haiku-4-5
GEMINI_API_KEY=<Gemini API 키>
```
