"""REST API mà n8n gọi tới. Chạy: uvicorn --factory sentinel.api:get_app --host 0.0.0.0 --port 8000"""

from __future__ import annotations

import hmac
import logging
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

from .claude import ClaudeAnalyst
from .config import Settings
from .models import TriageResult
from .pipeline import ActionError, Pipeline
from .report import confirm_page, message_page
from .small_llm import SmallLLM
from .store import Store
from .virustotal import VirusTotalClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def build_pipeline(settings: Settings) -> Pipeline:
    store = Store(settings.db_path)
    return Pipeline(
        settings=settings,
        store=store,
        vt=VirusTotalClient(settings, store),
        small_llm=SmallLLM(settings),
        claude=ClaudeAnalyst(settings),
    )


class ActionRequest(BaseModel):
    incident: str
    action: str
    token: str


def create_app(pipeline: Pipeline) -> FastAPI:
    settings = pipeline.settings
    app = FastAPI(title="Sentinel-FIM engine", version="0.1.0")

    def require_token(x_sentinel_token: str = Header(default="")) -> None:
        if not settings.api_token:
            raise HTTPException(503, "SENTINEL_API_TOKEN chưa được cấu hình")
        if not hmac.compare_digest(x_sentinel_token, settings.api_token):
            raise HTTPException(401, "Sai X-Sentinel-Token")

    auth = [Depends(require_token)]

    @app.get("/healthz")
    def healthz() -> dict:
        return {
            "status": "ok",
            "virustotal": pipeline.vt.enabled,
            "small_llm": pipeline.small_llm.enabled,
            "claude": pipeline.claude.enabled,
        }

    @app.post("/v1/triage", dependencies=auth, response_model=TriageResult)
    def triage(alert: dict[str, Any] = Body(...)) -> TriageResult:
        # Chấp nhận cả alert thô lẫn dạng {"alert": {...}} (một số cách forward của n8n).
        if "alert" in alert and isinstance(alert["alert"], dict) and "rule" not in alert:
            alert = alert["alert"]
        try:
            return pipeline.triage(alert)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.post("/v1/incidents/{incident_id}/analyze", dependencies=auth, response_model=TriageResult)
    def analyze(incident_id: str) -> TriageResult:
        try:
            return pipeline.analyze(incident_id)
        except KeyError as exc:
            raise HTTPException(404, "Không tìm thấy sự cố") from exc

    @app.get("/v1/incidents", dependencies=auth)
    def list_incidents(limit: int = Query(50, ge=1, le=500)) -> list[dict]:
        return [
            {
                "id": r["id"],
                "created_at": r["created_at"],
                "agent_id": r["agent_id"],
                "path": r["path"],
                "severity": r["severity"],
                "status": r["status"],
                "decision": r["decision"],
                "threat_label": r["data"]["virustotal"].get("threat_label", ""),
            }
            for r in pipeline.store.list_incidents(limit)
        ]

    @app.get("/v1/incidents/{incident_id}", dependencies=auth)
    def get_incident(incident_id: str) -> dict:
        record = pipeline.store.get_incident(incident_id)
        if record is None:
            raise HTTPException(404, "Không tìm thấy sự cố")
        return record

    @app.get("/v1/actions/confirm", dependencies=auth)
    def confirm(incident: str, action: str, token: str) -> dict:
        """Trả về trang HTML xác nhận để n8n hiển thị cho analyst (không thực thi gì)."""
        try:
            record = pipeline.check_action(incident, action, token)
        except ActionError as exc:
            return {"valid": False, "status_code": exc.status_code,
                    "html": message_page("Không thể thực hiện", exc.message)}
        return {"valid": True, "html": confirm_page(record, action, token, settings.action_base_url)}

    @app.post("/v1/actions/execute", dependencies=auth)
    def execute(req: ActionRequest) -> dict:
        try:
            result = pipeline.execute_action(req.incident, req.action, req.token)
        except ActionError as exc:
            return {"ok": False, "status_code": exc.status_code, "message": exc.message,
                    "html": message_page("Không thể thực hiện", exc.message)}
        result["html"] = message_page("Đã ghi nhận", result["message"])
        return result

    return app


def get_app() -> FastAPI:
    return create_app(build_pipeline(Settings.from_env()))
