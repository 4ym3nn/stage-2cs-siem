import csv
import io
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .database import Base, engine, get_db, upgrade_legacy_sqlite_schema
from .detections import RULES, run_detections
from .models import Alert, AlertNote, AuditLog, Case, Event
from .normalizers import normalize_linux, normalize_suricata, normalize_windows
from .schemas import AlertUpdate, CaseCreate, CaseUpdate, EventIn, NoteCreate
from .security import (
    analyst_identity,
    require_admin_key,
    require_analyst_key,
    require_ingest_key,
    require_read_access,
)


Base.metadata.create_all(bind=engine)
upgrade_legacy_sqlite_schema()
app = FastAPI(
    title="Stage 2CS SIEM",
    version="2.0.0",
    description="Educational SOC detection and investigation platform",
)
STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")


def _store_event(db: Session, item: EventIn):
    event = Event(
        timestamp=item.timestamp or datetime.now(timezone.utc),
        source=item.source.lower(),
        host=item.host,
        event_type=item.event_type,
        severity=item.severity.lower(),
        src_ip=item.src_ip,
        dst_ip=item.dst_ip,
        user=item.user,
        message=item.message,
        raw_json=json.dumps(item.raw, default=str),
    )
    db.add(event)
    db.flush()
    alerts = run_detections(db, event)
    return event, alerts


def _event_dict(event: Event, include_raw: bool = False) -> dict:
    result = {
        "id": event.id,
        "timestamp": event.timestamp,
        "source": event.source,
        "host": event.host,
        "event_type": event.event_type,
        "severity": event.severity,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "user": event.user,
        "message": event.message,
    }
    if include_raw:
        try:
            result["raw"] = json.loads(event.raw_json or "{}")
        except json.JSONDecodeError:
            result["raw"] = {"unparsed": event.raw_json}
    return result


def _alert_dict(alert: Alert, detailed: bool = False) -> dict:
    try:
        evidence = json.loads(alert.evidence or "{}")
    except json.JSONDecodeError:
        evidence = {"unparsed": alert.evidence}
    result = {
        "id": alert.id,
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
        "first_seen": alert.first_seen,
        "last_seen": alert.last_seen,
        "occurrence_count": alert.occurrence_count,
        "event_id": alert.event_id,
        "case_id": alert.case_id,
        "rule_id": alert.rule_id,
        "title": alert.title,
        "severity": alert.severity,
        "status": alert.status,
        "assignee": alert.assignee,
        "resolution_reason": alert.resolution_reason,
        "mitre_technique": alert.mitre_technique,
        "mitre_tactic": alert.mitre_tactic,
        "description": alert.description,
        "evidence": evidence,
    }
    if detailed:
        result["event"] = _event_dict(alert.event, include_raw=True) if alert.event else None
        result["notes"] = [
            {"id": note.id, "author": note.author, "body": note.body, "created_at": note.created_at}
            for note in sorted(alert.notes, key=lambda item: item.created_at)
        ]
    return result


def _case_dict(case: Case, detailed: bool = False) -> dict:
    result = {
        "id": case.id,
        "title": case.title,
        "description": case.description,
        "severity": case.severity,
        "status": case.status,
        "assignee": case.assignee,
        "created_at": case.created_at,
        "updated_at": case.updated_at,
        "alert_count": len(case.alerts),
    }
    if detailed:
        result["alerts"] = [_alert_dict(alert) for alert in case.alerts]
    return result


def _audit(db: Session, actor: str, action: str, target_type: str, target_id: int | None, details: dict) -> None:
    db.add(AuditLog(
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=json.dumps(details, default=str),
    ))


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "service": "Stage 2CS SIEM", "version": "2.0.0"}


@app.post("/api/events", dependencies=[Depends(require_ingest_key)])
def ingest_event(item: EventIn, db: Session = Depends(get_db)):
    event, alerts = _store_event(db, item)
    db.commit()
    return {"event_id": event.id, "alerts_created": [alert.id for alert in alerts]}


@app.post("/api/events/bulk", dependencies=[Depends(require_ingest_key)])
def ingest_bulk(items: list[EventIn], db: Session = Depends(get_db)):
    if len(items) > 5000:
        raise HTTPException(413, "A bulk request can contain at most 5000 events")
    created = alert_count = 0
    for item in items:
        _, alerts = _store_event(db, item)
        created += 1
        alert_count += len(alerts)
    db.commit()
    return {"events_created": created, "alerts_created": alert_count}


@app.post("/api/ingest/{source}", dependencies=[Depends(require_ingest_key)])
def ingest_normalized(source: str, payload: Any = Body(...), db: Session = Depends(get_db)):
    if source not in {"suricata", "linux", "windows"}:
        raise HTTPException(400, "source must be suricata, linux, or windows")
    records = payload if isinstance(payload, list) else [payload]
    if len(records) > 5000:
        raise HTTPException(413, "A bulk request can contain at most 5000 events")
    normalizer = {"suricata": normalize_suricata, "linux": normalize_linux, "windows": normalize_windows}[source]
    created = alert_count = 0
    for record in records:
        if not isinstance(record, dict):
            continue
        _, alerts = _store_event(db, normalizer(record))
        created += 1
        alert_count += len(alerts)
    db.commit()
    return {"events_created": created, "alerts_created": alert_count}


@app.get("/api/events", dependencies=[Depends(require_read_access)])
def list_events(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    source: str | None = None,
    severity: str | None = None,
    q: str | None = Query(default=None, max_length=200),
    db: Session = Depends(get_db),
):
    stmt = select(Event).order_by(Event.timestamp.desc()).offset(offset).limit(limit)
    if source:
        stmt = stmt.where(Event.source == source.lower())
    if severity:
        stmt = stmt.where(Event.severity == severity.lower())
    if q:
        stmt = stmt.where(Event.message.ilike(f"%{q}%"))
    return [_event_dict(event) for event in db.execute(stmt).scalars().all()]


@app.get("/api/alerts", dependencies=[Depends(require_read_access)])
def list_alerts(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: str | None = None,
    status: str | None = None,
    assignee: str | None = None,
    db: Session = Depends(get_db),
):
    stmt = select(Alert).order_by(Alert.last_seen.desc()).offset(offset).limit(limit)
    if severity:
        stmt = stmt.where(Alert.severity == severity.lower())
    if status:
        stmt = stmt.where(Alert.status == status.lower())
    if assignee:
        stmt = stmt.where(Alert.assignee == assignee)
    return [_alert_dict(alert) for alert in db.execute(stmt).scalars().all()]


@app.get("/api/alerts/{alert_id}", dependencies=[Depends(require_read_access)])
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "alert not found")
    return _alert_dict(alert, detailed=True)


@app.patch("/api/alerts/{alert_id}", dependencies=[Depends(require_analyst_key)])
def update_alert(
    alert_id: int,
    body: AlertUpdate,
    db: Session = Depends(get_db),
    actor: str = Depends(analyst_identity),
):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "alert not found")
    changes = body.model_dump(exclude_unset=True)
    if "case_id" in changes and changes["case_id"] is not None and not db.get(Case, changes["case_id"]):
        raise HTTPException(404, "case not found")
    for field, value in changes.items():
        setattr(alert, field, value)
    alert.updated_at = datetime.now(timezone.utc)
    _audit(db, actor, "alert.updated", "alert", alert.id, changes)
    db.commit()
    return _alert_dict(alert)


@app.post("/api/alerts/{alert_id}/notes", dependencies=[Depends(require_analyst_key)])
def add_alert_note(
    alert_id: int,
    body: NoteCreate,
    db: Session = Depends(get_db),
    actor: str = Depends(analyst_identity),
):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "alert not found")
    note = AlertNote(alert_id=alert.id, author=body.author, body=body.body)
    db.add(note)
    _audit(db, actor, "alert.note_added", "alert", alert.id, {"author": body.author})
    db.commit()
    db.refresh(note)
    return {"id": note.id, "author": note.author, "body": note.body, "created_at": note.created_at}


@app.get("/api/cases", dependencies=[Depends(require_read_access)])
def list_cases(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: str | None = None,
    db: Session = Depends(get_db),
):
    stmt = select(Case).order_by(Case.updated_at.desc()).offset(offset).limit(limit)
    if status:
        stmt = stmt.where(Case.status == status.lower())
    return [_case_dict(case) for case in db.execute(stmt).scalars().all()]


@app.post("/api/cases", dependencies=[Depends(require_analyst_key)])
def create_case(
    body: CaseCreate,
    db: Session = Depends(get_db),
    actor: str = Depends(analyst_identity),
):
    case = Case(
        title=body.title,
        description=body.description,
        severity=body.severity,
        assignee=body.assignee,
    )
    db.add(case)
    db.flush()
    if body.alert_ids:
        alerts = db.execute(select(Alert).where(Alert.id.in_(body.alert_ids))).scalars().all()
        if len(alerts) != len(set(body.alert_ids)):
            raise HTTPException(404, "one or more alerts were not found")
        for alert in alerts:
            alert.case_id = case.id
    _audit(db, actor, "case.created", "case", case.id, {"alert_ids": body.alert_ids})
    db.commit()
    return _case_dict(case, detailed=True)


@app.get("/api/cases/{case_id}", dependencies=[Depends(require_read_access)])
def get_case(case_id: int, db: Session = Depends(get_db)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "case not found")
    return _case_dict(case, detailed=True)


@app.patch("/api/cases/{case_id}", dependencies=[Depends(require_analyst_key)])
def update_case(
    case_id: int,
    body: CaseUpdate,
    db: Session = Depends(get_db),
    actor: str = Depends(analyst_identity),
):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "case not found")
    changes = body.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(case, field, value)
    case.updated_at = datetime.now(timezone.utc)
    _audit(db, actor, "case.updated", "case", case.id, changes)
    db.commit()
    return _case_dict(case, detailed=True)


@app.get("/api/rules", dependencies=[Depends(require_read_access)])
def rules():
    return RULES


@app.get("/api/stats", dependencies=[Depends(require_read_access)])
def stats(db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    since_24h = now - timedelta(hours=24)
    total_events = db.scalar(select(func.count(Event.id))) or 0
    events_24h = db.scalar(select(func.count(Event.id)).where(Event.timestamp >= since_24h)) or 0
    open_alerts = db.scalar(select(func.count(Alert.id)).where(Alert.status == "open")) or 0
    critical_open = db.scalar(select(func.count(Alert.id)).where(Alert.status == "open", Alert.severity == "critical")) or 0
    open_cases = db.scalar(select(func.count(Case.id)).where(Case.status != "closed")) or 0
    severity_rows = db.execute(select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)).all()
    source_rows = db.execute(select(Event.source, func.count(Event.id)).group_by(Event.source)).all()
    return {
        "total_events": total_events,
        "events_24h": events_24h,
        "open_alerts": open_alerts,
        "critical_open": critical_open,
        "open_cases": open_cases,
        "alerts_by_severity": dict(severity_rows),
        "events_by_source": dict(source_rows),
    }


@app.get("/api/export/alerts.csv", dependencies=[Depends(require_read_access)])
def export_alerts(db: Session = Depends(get_db)):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "last_seen", "severity", "rule_id", "title", "status", "assignee", "occurrences", "case_id"])
    for alert in db.execute(select(Alert).order_by(Alert.last_seen.desc())).scalars():
        writer.writerow([
            alert.id, alert.last_seen, alert.severity, alert.rule_id, alert.title,
            alert.status, alert.assignee or "", alert.occurrence_count, alert.case_id or "",
        ])
    headers = {"Content-Disposition": "attachment; filename=stage-2cs-siem-alerts.csv"}
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers=headers)


@app.get("/api/audit", dependencies=[Depends(require_admin_key)])
def audit_log(limit: int = Query(100, ge=1, le=1000), db: Session = Depends(get_db)):
    rows = db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)).scalars().all()
    return [
        {
            "id": row.id,
            "created_at": row.created_at,
            "actor": row.actor,
            "action": row.action,
            "target_type": row.target_type,
            "target_id": row.target_id,
            "details": json.loads(row.details or "{}"),
        }
        for row in rows
    ]


@app.post("/api/admin/cleanup", dependencies=[Depends(require_admin_key)])
def cleanup(db: Session = Depends(get_db), actor: str = Depends(analyst_identity)):
    days = max(1, int(os.getenv("SIEM_RETENTION_DAYS", "30")))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    old_event_ids = select(Event.id).where(Event.timestamp < cutoff)
    old_alert_ids = select(Alert.id).where(Alert.event_id.in_(old_event_ids))
    db.execute(delete(AlertNote).where(AlertNote.alert_id.in_(old_alert_ids)))
    db.execute(delete(Alert).where(Alert.event_id.in_(old_event_ids)))
    result = db.execute(delete(Event).where(Event.timestamp < cutoff))
    _audit(db, actor, "retention.cleanup", "events", None, {"deleted_events": result.rowcount, "retention_days": days})
    db.commit()
    return {"deleted_events": result.rowcount, "retention_days": days}
