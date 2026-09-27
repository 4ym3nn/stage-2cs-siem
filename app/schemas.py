from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class EventIn(BaseModel):
    timestamp: datetime | None = None
    source: str = Field(default="api", max_length=32)
    host: str = Field(default="unknown", max_length=255)
    event_type: str = Field(default="generic", max_length=64)
    severity: str = Field(default="info", max_length=16)
    src_ip: str | None = None
    dst_ip: str | None = None
    user: str | None = None
    message: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class EventOut(EventIn):
    id: int


class AlertOut(BaseModel):
    id: int
    created_at: datetime
    event_id: int | None
    rule_id: str
    title: str
    severity: str
    status: str
    mitre_technique: str | None
    mitre_tactic: str | None
    description: str
    evidence: dict[str, Any]


class AlertStatusUpdate(BaseModel):
    status: str = Field(pattern="^(open|investigating|closed|false_positive)$")


class AlertUpdate(BaseModel):
    status: str | None = Field(default=None, pattern="^(open|investigating|closed|false_positive)$")
    assignee: str | None = Field(default=None, max_length=255)
    resolution_reason: str | None = Field(default=None, max_length=2000)
    case_id: int | None = None


class NoteCreate(BaseModel):
    author: str = Field(default="analyst", min_length=1, max_length=255)
    body: str = Field(min_length=1, max_length=4000)


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=4000)
    severity: str = Field(default="medium", pattern="^(critical|high|medium|low|info)$")
    assignee: str | None = Field(default=None, max_length=255)
    alert_ids: list[int] = Field(default_factory=list, max_length=100)


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4000)
    severity: str | None = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    status: str | None = Field(default=None, pattern="^(open|investigating|closed)$")
    assignee: str | None = Field(default=None, max_length=255)
