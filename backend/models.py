"""Pydantic data models for the Local AI Security Log Analyzer."""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Core data models
# ---------------------------------------------------------------------------

class EvidenceItem(BaseModel):
    """A single piece of evidence tied to a log line number."""
    line: int
    description: str = ""


class Finding(BaseModel):
    """A security finding detected by the analyzer."""
    id: int = 0
    attack_type: str
    severity: Severity
    source_ip: str
    evidence: list[EvidenceItem] = Field(default_factory=list)
    reason: str = ""
    recommended_action: str = ""


class LogChunk(BaseModel):
    """A segment of the log file sized to fit the model's token budget."""
    index: int
    start_line: int
    end_line: int
    line_count: int
    token_count: int
    text: str


class ChunkResult(BaseModel):
    """The outcome of analysing a single chunk."""
    chunk_index: int
    start_line: int
    end_line: int
    findings: list[Finding] = Field(default_factory=list)
    raw_response: str = ""
    success: bool = True
    error: Optional[str] = None
    duration_ms: int = 0


# ---------------------------------------------------------------------------
# Job tracking
# ---------------------------------------------------------------------------

class AnalysisJob(BaseModel):
    """Tracks the full lifecycle of a log-analysis request."""
    job_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    status: JobStatus = JobStatus.QUEUED
    filename: str = ""
    total_lines: int = 0
    total_chunks: int = 0
    chunks_completed: int = 0
    current_chunk: int = 0
    chunk_results: list[ChunkResult] = Field(default_factory=list)
    merged_findings: list[Finding] = Field(default_factory=list)
    started_at: float = 0.0
    completed_at: float = 0.0
    error: Optional[str] = None

    @property
    def duration_seconds(self) -> float:
        end = self.completed_at or time.time()
        return round(end - self.started_at, 1) if self.started_at else 0.0

    @property
    def progress_pct(self) -> int:
        if self.total_chunks == 0:
            return 0
        return int(self.chunks_completed / self.total_chunks * 100)

