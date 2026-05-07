import base64
import json
import os
from datetime import datetime

RECON_BASE_DIR = os.getenv("RECON_BASE_DIR", "/data/recon")


def ensure_recon_dirs():
    os.makedirs(RECON_BASE_DIR, exist_ok=True)


def _safe_filename(filename: str) -> str:
    """
    경로 조작 방지용.
    예: ../../test.html 같은 값이 와도 test.html만 사용.
    """
    return os.path.basename(filename or "").strip()


def _save_artifacts(payload: dict, run_dir: str, latest_dir: str) -> list[dict]:
    """
    payload["artifacts"] 형태:
    [
      {
        "filename": "ad_hc_lab.local.html",
        "mime_type": "text/html",
        "content_base64": "..."
      }
    ]
    """
    artifacts = payload.get("artifacts") or []
    saved_artifacts = []

    if not isinstance(artifacts, list):
        return saved_artifacts

    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue

        filename = _safe_filename(artifact.get("filename", ""))
        content_base64 = artifact.get("content_base64", "")
        mime_type = artifact.get("mime_type", "application/octet-stream")

        if not filename or not content_base64:
            continue

        try:
            content = base64.b64decode(content_base64)
        except Exception:
            continue

        run_artifact_path = os.path.join(run_dir, filename)
        latest_artifact_path = os.path.join(latest_dir, filename)

        with open(run_artifact_path, "wb") as f:
            f.write(content)

        with open(latest_artifact_path, "wb") as f:
            f.write(content)

        saved_artifacts.append({
            "filename": filename,
            "mime_type": mime_type,
            "path": run_artifact_path,
            "latest_path": latest_artifact_path,
            "size": len(content),
        })

    return saved_artifacts


def save_recon_result(payload: dict):
    ensure_recon_dirs()

    tool = payload.get("tool", "unknown")
    query_type = payload.get("query_type", "general")
    run_id = payload.get("run_id") or f"recon-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    tool_dir = os.path.join(RECON_BASE_DIR, tool)
    latest_dir = os.path.join(tool_dir, "latest")
    run_dir = os.path.join(tool_dir, run_id)

    os.makedirs(tool_dir, exist_ok=True)
    os.makedirs(latest_dir, exist_ok=True)
    os.makedirs(run_dir, exist_ok=True)

    # 1. HTML/XML 같은 첨부 파일 먼저 저장
    saved_artifacts = _save_artifacts(payload, run_dir, latest_dir)

    # 2. payload/summary에도 저장된 파일 정보 반영
    if saved_artifacts:
        payload["saved_artifacts"] = saved_artifacts

        summary = payload.get("summary")
        if not isinstance(summary, dict):
            summary = {}

        summary["artifacts"] = saved_artifacts
        payload["summary"] = summary

    raw_path = os.path.join(run_dir, "result.json")
    summary_path = os.path.join(run_dir, "summary.json")

    with open(raw_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(payload.get("summary", {}), f, ensure_ascii=False, indent=2)

    with open(os.path.join(latest_dir, "result.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    with open(os.path.join(latest_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(payload.get("summary", {}), f, ensure_ascii=False, indent=2)

    return {
        "result": "saved",
        "tool": tool,
        "query_type": query_type,
        "run_id": run_id,
        "path": raw_path,
        "saved_artifacts": saved_artifacts,
    }


def get_latest_recon_result(tool: str):
    latest_path = os.path.join(RECON_BASE_DIR, tool, "latest", "result.json")
    if not os.path.exists(latest_path):
        return {"result": "empty", "tool": tool}

    with open(latest_path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_latest_recon_summary(tool: str):
    latest_path = os.path.join(RECON_BASE_DIR, tool, "latest", "summary.json")
    if not os.path.exists(latest_path):
        return {"result": "empty", "tool": tool}

    with open(latest_path, "r", encoding="utf-8") as f:
        return json.load(f)