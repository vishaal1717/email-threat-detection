from __future__ import annotations

import csv
import io

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from .analyze import analyze_email
from .db import get_analysis, init_db, list_analyses, save_analysis


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Email Threat Intelligence API",
    description="Demo backend for hop maps, MITRE ATT&CK labels, and IOC export.",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRawRequest(BaseModel):
    headers: str
    body: str = ""


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/analyze/raw")
def analyze_raw(payload: AnalyzeRawRequest) -> dict:
    result = analyze_email(payload.headers, payload.body)
    return save_analysis(result)


@app.get("/api/analyses")
def analyses(limit: int = 50) -> list[dict]:
    return list_analyses(limit)


@app.get("/api/analyses/{analysis_id}")
def analysis_detail(analysis_id: int) -> dict:
    row = get_analysis(analysis_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return row


@app.get("/api/analyses/{analysis_id}/iocs.csv")
def export_iocs(analysis_id: int) -> StreamingResponse:
    row = get_analysis(analysis_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Analysis not found")

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["type", "value"])
    for kind, values in (row.get("iocs") or {}).items():
        for value in values:
            writer.writerow([kind, value])
    buffer.seek(0)
    filename = f"iocs-{analysis_id}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
