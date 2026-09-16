"""HTTP API and server-sent event stream for the SOC dashboard."""

from __future__ import annotations

import asyncio
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .features import FEATURES
from .model import DEFAULT_MODEL_DIR, Detector
from .runtime import SCENARIO_CATALOG, Runtime
from .schema import LAYERS, Event

ROOT = Path(__file__).resolve().parent.parent
WEB_DIST = Path(os.environ.get("VIGIL_WEB_DIST", ROOT / "web" / "dist"))
MODEL_DIR = Path(os.environ.get("VIGIL_MODEL_DIR", DEFAULT_MODEL_DIR))
FEEDBACK = Path(os.environ.get("VIGIL_FEEDBACK", ROOT / "data" / "feedback.jsonl"))
CORS_ORIGINS = os.environ.get("VIGIL_CORS", "http://localhost:5190,http://127.0.0.1:5190").split(",")


class StatusUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved", "false_positive"]
    note: str | None = Field(default=None, max_length=500)


class LaunchRequest(BaseModel):
    scenario: str
    intensity: float = Field(default=1.0, ge=0.5, le=2.0)


class SettingsUpdate(BaseModel):
    speed: float | None = Field(default=None, ge=1, le=120)
    ambient: bool | None = None
    paused: bool | None = None


class IngestEvent(BaseModel):
    ts: float | None = None
    layer: Literal["network", "endpoint", "application"]
    kind: Literal["flow", "auth", "process", "http"]
    src_ip: str
    dst_ip: str
    dst_port: int = 0
    bytes_out: int = Field(default=0, ge=0)
    bytes_in: int = Field(default=0, ge=0)
    duration: float = Field(default=0.0, ge=0)
    user: str | None = None
    outcome: Literal["success", "failure"] | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    process: str | None = None


def create_app(runtime: Runtime | None = None, start_loop: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        rt = runtime or Runtime(Detector.load(MODEL_DIR), feedback_path=FEEDBACK)
        app.state.runtime = rt
        app.state.metrics = _load_metrics()
        if start_loop:
            await rt.start()
        yield
        await rt.stop()

    app = FastAPI(title="Vigil SOC API", version="1.0.0", lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_methods=["*"], allow_headers=["*"])

    def rt(request: Request) -> Runtime:
        return request.app.state.runtime

    @app.get("/api/health")
    def health(request: Request):
        r = rt(request)
        return {"status": "ok", "model_version": r.detector.meta.get("version"), "sim_time": r.now}

    @app.get("/api/overview")
    def overview(request: Request):
        return rt(request).overview()

    @app.get("/api/alerts")
    def list_alerts(
        request: Request,
        status: str | None = None,
        severity: str | None = None,
        threat: str | None = None,
        q: str | None = None,
        limit: int = Query(200, ge=1, le=2000),
    ):
        items = rt(request).alerts()
        if status:
            wanted = set(status.split(","))
            items = [a for a in items if a["status"] in wanted]
        if severity:
            wanted = set(severity.split(","))
            items = [a for a in items if a["severity"] in wanted]
        if threat:
            items = [a for a in items if a["threat"] == threat]
        if q:
            needle = q.lower()
            items = [a for a in items if needle in " ".join(
                str(a.get(k) or "") for k in ("id", "entity", "hostname", "title", "summary")).lower()]
        return items[:limit]

    @app.get("/api/alerts/{alert_id}")
    def get_alert(alert_id: str, request: Request):
        try:
            return rt(request).alert(alert_id)
        except KeyError:
            raise HTTPException(404, f"Alert {alert_id} not found")

    @app.patch("/api/alerts/{alert_id}")
    def update_alert(alert_id: str, body: StatusUpdate, request: Request):
        try:
            return rt(request).set_alert_status(alert_id, body.status, body.note)
        except KeyError:
            raise HTTPException(404, f"Alert {alert_id} not found")

    @app.get("/api/incidents")
    def list_incidents(request: Request):
        return rt(request).incidents()

    @app.get("/api/incidents/{incident_id}")
    def get_incident(incident_id: str, request: Request):
        try:
            return rt(request).incident(incident_id)
        except KeyError:
            raise HTTPException(404, f"Incident {incident_id} not found")

    @app.get("/api/scenarios")
    def scenarios():
        return SCENARIO_CATALOG

    @app.get("/api/simulations")
    def list_runs(request: Request):
        return rt(request).list_runs()

    @app.post("/api/simulations", status_code=201)
    def launch(body: LaunchRequest, request: Request):
        try:
            return rt(request).launch(body.scenario, body.intensity)
        except KeyError:
            raise HTTPException(404, f"Unknown scenario {body.scenario}")

    @app.post("/api/simulations/{run_id}/stop")
    def stop(run_id: str, request: Request):
        try:
            return rt(request).stop_run(run_id)
        except KeyError:
            raise HTTPException(404, f"Run {run_id} not found")

    @app.get("/api/settings")
    def get_settings(request: Request):
        return rt(request).settings()

    @app.patch("/api/settings")
    def patch_settings(body: SettingsUpdate, request: Request):
        return rt(request).update_settings(body.speed, body.ambient, body.paused)

    @app.post("/api/reset")
    def reset(request: Request):
        rt(request).reset()
        return {"status": "reset"}

    @app.post("/api/ingest", status_code=202)
    def ingest(events: list[IngestEvent], request: Request):
        """Accept raw telemetry from an external collector."""
        if len(events) > 10_000:
            raise HTTPException(413, "At most 10,000 events per request")
        r = rt(request)
        now = r.now
        accepted = r.ingest([Event(**{**e.model_dump(), "ts": e.ts if e.ts is not None else now}) for e in events])
        return {"accepted": accepted}

    @app.get("/api/model")
    def model(request: Request):
        r = rt(request)
        return {
            "meta": r.detector.info(),
            "metrics": request.app.state.metrics,
            "features": [{"name": f.name, "label": f.label, "kind": f.kind} for f in FEATURES],
            "layers": LAYERS,
        }

    @app.get("/api/stream")
    async def stream(request: Request):
        r = rt(request)
        queue = r.subscribe()

        async def events():
            try:
                yield f"event: hello\ndata: {json.dumps({'server_time': time.time()})}\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        yield await asyncio.wait_for(queue.get(), timeout=15)
                    except asyncio.TimeoutError:
                        yield ": keep-alive\n\n"
            finally:
                r.unsubscribe(queue)

        return StreamingResponse(events(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    if WEB_DIST.is_dir():
        app.mount("/assets", StaticFiles(directory=WEB_DIST / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            candidate = (WEB_DIST / path).resolve()
            if path and candidate.is_file() and WEB_DIST.resolve() in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(WEB_DIST / "index.html")

    return app


def _load_metrics() -> dict | None:
    path = MODEL_DIR / "metrics.json"
    return json.loads(path.read_text()) if path.exists() else None


app = create_app()
