from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .guards import make_classifier
from .pipeline import handle
from .target import make_target

STATIC = Path(__file__).parent / "static"


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    document: str | None = Field(default=None, max_length=50_000)


def create_app(dsn: str | None = None) -> FastAPI:
    app = FastAPI(title="Guarded HR assistant + red-team dashboard", version="1.0.0")
    target, classifier = make_target(), make_classifier()
    conn = None
    if dsn is not False:
        from .db import connect

        conn = connect(dsn)

    @app.post("/chat")
    def chat(req: ChatRequest):
        r = handle(target, classifier, req.message, req.document)
        return {"response": r["response"], "blocked": r["blocked"], "blocked_by": r["blocked_by"]}

    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(STATIC / "dashboard.html")

    @app.get("/api/runs")
    def runs():
        return conn.execute(
            "select id, suite_name, suite_version, mode, target, classifier, created_at, summary"
            " from replay_runs order by id desc limit 50"
        ).fetchall()

    @app.get("/api/runs/{run_id}/attempts")
    def attempts(run_id: int, config: str = "full"):
        rows = conn.execute(
            "select case_id, category, blocked, blocked_by, succeeded, input, response, latency_ms"
            " from attempts where run_id = %s and config = %s order by case_id",
            (run_id, config),
        ).fetchall()
        if not rows:
            raise HTTPException(404, "no attempts for that run/config")
        return rows

    return app
