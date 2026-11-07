"""
FastAPI application – the web server for the Local AI Security Log Analyzer.

Endpoints
---------
GET  /                    Serve the single-page frontend
POST /api/upload          Accept a .log / .txt file and start analysis
GET  /api/status/{id}     Server-Sent Events stream of progress
GET  /api/report/{id}     Final merged report JSON
GET  /api/health          Backend + Ollama health check
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from backend import config
from backend.analyzer import analyze_chunk, build_context_summary
from backend.merger import merge_findings
from backend.models import AnalysisJob, Finding, JobStatus
from backend.splitter import split_log_file

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="Local AI Security Log Analyzer")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory job store (sufficient for single-user assessment scenario)
_jobs: dict[str, AnalysisJob] = {}

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
FRONTEND_DIR = BASE_DIR / "frontend"


# ===================================================================
# Routes
# ===================================================================

@app.get("/")
async def serve_frontend():
    """Serve the single-page dashboard."""
    index = FRONTEND_DIR / "index.html"
    if not index.exists():
        raise HTTPException(500, "Frontend not found. Ensure frontend/index.html exists.")
    return FileResponse(index, media_type="text/html")


@app.get("/Cultive8_Workspace_Agrigen_Server.log")
@app.get("/api/sample")
async def get_sample_log():
    """Serve the assessment sample log file for 1-click loading."""
    sample_file = BASE_DIR / "Cultive8_Workspace_Agrigen_Server.log"
    if not sample_file.exists():
        raise HTTPException(404, "Sample log file not found.")
    return FileResponse(sample_file, media_type="text/plain", filename="Cultive8_Workspace_Agrigen_Server.log")


@app.post("/api/upload")
async def upload_log(file: UploadFile):
    """Upload a log file, validate it, and start background analysis."""

    # ---- validate extension ----
    filename = file.filename or "upload.log"
    ext = Path(filename).suffix.lower()
    if ext not in config.ALLOWED_EXTENSIONS:
        raise HTTPException(
            400,
            f"Invalid file type '{ext}'. Allowed: {', '.join(sorted(config.ALLOWED_EXTENSIONS))}",
        )

    # ---- validate size ----
    content = await file.read()
    if len(content) > config.MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            400,
            f"File too large ({len(content):,} bytes). Maximum: {config.MAX_FILE_SIZE_BYTES:,} bytes.",
        )
    if not content.strip():
        raise HTTPException(400, "File is empty.")

    # ---- persist to disk ----
    job = AnalysisJob(filename=filename)
    save_path = UPLOAD_DIR / f"{job.job_id}_{filename}"
    save_path.write_bytes(content)

    _jobs[job.job_id] = job

    # ---- launch background analysis ----
    thread = threading.Thread(
        target=_run_analysis,
        args=(job.job_id, str(save_path)),
        daemon=True,
        name=f"analysis-{job.job_id}",
    )
    thread.start()

    return {
        "job_id": job.job_id,
        "filename": filename,
        "size_bytes": len(content),
    }


@app.get("/api/status/{job_id}")
async def job_status_sse(job_id: str):
    """Stream analysis progress as Server-Sent Events."""
    if job_id not in _jobs:
        raise HTTPException(404, "Job not found.")
    return StreamingResponse(
        _sse_stream(job_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/report/{job_id}")
async def get_report(job_id: str):
    """Return the final merged report once analysis is complete."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "Job not found.")
    if job.status not in (JobStatus.COMPLETED, JobStatus.FAILED):
        return JSONResponse(
            {"message": "Analysis still in progress.", "progress_pct": job.progress_pct},
            status_code=202,
        )
    return _build_report(job)


@app.get("/api/health")
async def health_check():
    """Check backend and Ollama availability."""
    ollama_ok = False
    ollama_models: list[str] = []
    try:
        import requests as req

        r = req.get(f"{config.OLLAMA_BASE_URL}/api/tags", timeout=5)
        if r.status_code == 200:
            ollama_ok = True
            ollama_models = [
                m.get("name", "") for m in r.json().get("models", [])
            ]
    except Exception:
        pass

    return {
        "status": "ok",
        "ollama_connected": ollama_ok,
        "ollama_models": ollama_models,
        "configured_model": config.OLLAMA_MODEL,
        "token_budget": {
            "max_context": config.MAX_CONTEXT_TOKENS,
            "system_prompt": config.SYSTEM_PROMPT_BUDGET,
            "context_carry": config.CONTEXT_CARRY_BUDGET,
            "data": config.DATA_TOKEN_BUDGET,
            "output": config.OUTPUT_TOKEN_BUDGET,
        },
        "active_jobs": sum(
            1 for j in _jobs.values() if j.status == JobStatus.RUNNING
        ),
    }


# ===================================================================
# Background analysis pipeline
# ===================================================================

def _run_analysis(job_id: str, file_path: str) -> None:
    """Execute the full analysis pipeline in a background thread."""
    job = _jobs[job_id]
    job.status = JobStatus.RUNNING
    job.started_at = time.time()

    try:
        # ---- Step 1: split ----
        logger.info("Splitting log file: %s", file_path)
        chunks = split_log_file(file_path, config.DATA_TOKEN_BUDGET)
        job.total_lines = sum(c.line_count for c in chunks)
        job.total_chunks = len(chunks)

        if not chunks:
            job.status = JobStatus.FAILED
            job.error = "No valid log lines found in the uploaded file."
            job.completed_at = time.time()
            return

        logger.info(
            "Split into %d chunks (%d lines total)",
            len(chunks), job.total_lines,
        )

        # ---- Step 2: analyse each chunk sequentially ----
        all_findings: list[Finding] = []
        context_summary = ""

        for chunk in chunks:
            job.current_chunk = chunk.index + 1

            result = analyze_chunk(chunk, context_summary)
            job.chunk_results.append(result)

            if result.success:
                all_findings.extend(result.findings)
                context_summary = build_context_summary(
                    all_findings, config.CONTEXT_CARRY_BUDGET,
                )

            job.chunks_completed = chunk.index + 1
            logger.info(
                "Chunk %d/%d done  (%.0f s elapsed, %d raw findings so far)",
                job.chunks_completed,
                job.total_chunks,
                time.time() - job.started_at,
                len(all_findings),
            )

        # ---- Step 3: merge & correlate ----
        logger.info("Merging %d raw findings …", len(all_findings))
        job.merged_findings = merge_findings(all_findings)

        job.status = JobStatus.COMPLETED
        job.completed_at = time.time()
        logger.info(
            "Analysis complete: %d merged findings in %.1f s",
            len(job.merged_findings),
            job.duration_seconds,
        )

    except Exception as exc:
        logger.exception("Analysis failed for job %s", job_id)
        job.status = JobStatus.FAILED
        job.error = str(exc)
        job.completed_at = time.time()


# ===================================================================
# SSE helpers
# ===================================================================

async def _sse_stream(job_id: str) -> AsyncGenerator[str, None]:
    """Yield SSE events until the job finishes."""
    while True:
        job = _jobs.get(job_id)
        if not job:
            yield _sse("error", {"message": "Job not found"})
            return

        payload = {
            "status": job.status.value,
            "progress_pct": job.progress_pct,
            "current_chunk": job.current_chunk,
            "total_chunks": job.total_chunks,
            "chunks_completed": job.chunks_completed,
            "elapsed_seconds": job.duration_seconds,
            "findings_so_far": sum(
                len(r.findings) for r in job.chunk_results
            ),
        }

        if job.status == JobStatus.COMPLETED:
            payload["report"] = _build_report(job)
            yield _sse("complete", payload)
            return

        if job.status == JobStatus.FAILED:
            payload["error"] = job.error
            yield _sse("error", payload)
            return

        yield _sse("progress", payload)
        await asyncio.sleep(1)


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ===================================================================
# Report builder
# ===================================================================

def _build_report(job: AnalysisJob) -> dict:
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in job.merged_findings:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

    return {
        "summary": {
            "filename": job.filename,
            "total_lines_analyzed": job.total_lines,
            "chunks_processed": job.total_chunks,
            "chunks_succeeded": sum(1 for r in job.chunk_results if r.success),
            "chunks_failed": sum(1 for r in job.chunk_results if not r.success),
            "total_findings": len(job.merged_findings),
            "severity_counts": sev_counts,
            "analysis_duration_seconds": job.duration_seconds,
            "model_used": config.OLLAMA_MODEL,
        },
        "findings": [f.model_dump() for f in job.merged_findings],
        "chunk_details": [
            {
                "chunk": r.chunk_index + 1,
                "lines": f"{r.start_line}–{r.end_line}",
                "success": r.success,
                "findings_count": len(r.findings),
                "duration_ms": r.duration_ms,
                "error": r.error,
            }
            for r in job.chunk_results
        ],
    }

