import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .models import Alert, Event


RULE_FILE = Path(__file__).resolve().parents[1] / "config" / "detection_rules.yml"


def load_rules() -> dict:
    with RULE_FILE.open(encoding="utf-8") as handle:
        rules = yaml.safe_load(handle) or {}
    required = {"title", "severity", "description", "enabled"}
    for rule_id, rule in rules.items():
        missing = required - set(rule)
        if missing:
            raise RuntimeError(f"Rule {rule_id} is missing: {', '.join(sorted(missing))}")
    return rules


RULES = load_rules()


def _event_time(event: Event) -> datetime:
    value = event.timestamp or datetime.now(timezone.utc)
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _upsert_alert(
    db: Session,
    event: Event,
    rule_id: str,
    evidence: dict,
    scope: str,
) -> tuple[Alert | None, bool]:
    """Create an alert or aggregate it into a recent alert with the same scope."""
    rule = RULES[rule_id]
    if not rule.get("enabled", True):
        return None, False

    anchor = _event_time(event)
    suppression_key = f"{rule_id}:{scope}"[:512]
    cooldown = int(rule.get("cooldown_seconds", 0))
    existing = None
    if cooldown:
        existing = db.scalar(
            select(Alert)
            .where(
                Alert.rule_id == rule_id,
                Alert.suppression_key == suppression_key,
                Alert.status.in_(["open", "investigating"]),
                Alert.last_seen >= anchor - timedelta(seconds=cooldown),
            )
            .order_by(Alert.last_seen.desc())
            .limit(1)
        )

    if existing:
        existing.event_id = event.id
        existing.last_seen = anchor
        existing.updated_at = datetime.now(timezone.utc)
        existing.occurrence_count += 1
        existing.evidence = json.dumps(evidence, default=str)
        db.flush()
        return existing, False

    alert = Alert(
        event_id=event.id,
        rule_id=rule_id,
        suppression_key=suppression_key,
        title=rule["title"],
        severity=rule["severity"],
        mitre_technique=rule.get("mitre_technique"),
        mitre_tactic=rule.get("mitre_tactic"),
        description=rule["description"],
        evidence=json.dumps(evidence, default=str),
        first_seen=anchor,
        last_seen=anchor,
    )
    db.add(alert)
    db.flush()
    return alert, True


def _count_recent(db: Session, where: list, seconds: int, anchor: datetime) -> int:
    since = anchor - timedelta(seconds=seconds)
    return db.scalar(
        select(func.count(Event.id)).where(
            Event.timestamp >= since,
            Event.timestamp <= anchor,
            *where,
        )
    ) or 0


def _emit(alerts: list[Alert], result: tuple[Alert | None, bool]) -> None:
    alert, created = result
    if alert is not None and created:
        alerts.append(alert)


def run_detections(db: Session, event: Event) -> list[Alert]:
    alerts: list[Alert] = []
    msg = (event.message or "").lower()
    raw = (event.raw_json or "{}").lower()
    anchor = _event_time(event)

    is_failed_ssh = event.source == "linux" and (
        "failed password" in msg or event.event_type in {"failed_logon", "ssh_failed"}
    )
    if is_failed_ssh and event.src_ip:
        rule = RULES["LINUX-SSH-BRUTE"]
        count = _count_recent(
            db,
            [
                Event.source == "linux",
                Event.src_ip == event.src_ip,
                or_(Event.message.ilike("%failed%"), Event.event_type.in_(["failed_logon", "ssh_failed"])),
            ],
            int(rule["window_seconds"]),
            anchor,
        )
        if count >= int(rule["threshold"]):
            _emit(alerts, _upsert_alert(
                db, event, "LINUX-SSH-BRUTE",
                {"src_ip": event.src_ip, "failures": count, "window_seconds": rule["window_seconds"]},
                event.src_ip,
            ))

    if "fail" in msg or event.event_type == "failed_logon":
        rule = RULES["AUTH-FAIL-BURST"]
        filters = [or_(Event.message.ilike("%fail%"), Event.event_type == "failed_logon")]
        identity = event.user or event.src_ip or event.host
        if event.user:
            filters.append(Event.user == event.user)
        elif event.src_ip:
            filters.append(Event.src_ip == event.src_ip)
        count = _count_recent(db, filters, int(rule["window_seconds"]), anchor)
        if count >= int(rule["threshold"]):
            _emit(alerts, _upsert_alert(
                db, event, "AUTH-FAIL-BURST",
                {"user": event.user, "src_ip": event.src_ip, "failures": count, "window_seconds": rule["window_seconds"]},
                str(identity),
            ))

    try:
        record = json.loads(event.raw_json or "{}")
    except (TypeError, json.JSONDecodeError):
        record = {}
    destination_port = record.get("dest_port") or record.get("dst_port")
    if event.src_ip and destination_port:
        rule = RULES["NET-PORT-SCAN"]
        since = anchor - timedelta(seconds=int(rule["window_seconds"]))
        rows = db.execute(
            select(Event.raw_json).where(
                Event.timestamp >= since,
                Event.timestamp <= anchor,
                Event.src_ip == event.src_ip,
            )
        ).scalars().all()
        ports: set[int] = set()
        for row in rows:
            try:
                parsed = json.loads(row)
                port = parsed.get("dest_port") or parsed.get("dst_port")
                if port is not None:
                    ports.add(int(port))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
        if len(ports) >= int(rule["threshold"]):
            _emit(alerts, _upsert_alert(
                db, event, "NET-PORT-SCAN",
                {"src_ip": event.src_ip, "distinct_ports": len(ports), "ports": sorted(ports)[:50]},
                event.src_ip,
            ))

    if event.source == "linux" and ("sudo" in msg or event.user == "root"):
        _emit(alerts, _upsert_alert(
            db, event, "PRIV-SUDO-ROOT",
            {"user": event.user, "message": event.message[:500]},
            f"{event.host}:{event.user or 'unknown'}",
        ))

    if event.source == "windows" and (
        event.event_type == "group_member_added"
        or any(value in msg for value in ["administrators", "domain admins", "enterprise admins"])
    ):
        _emit(alerts, _upsert_alert(
            db, event, "WIN-PRIV-GROUP",
            {"user": event.user, "message": event.message[:500]},
            f"{event.host}:{event.user or 'unknown'}",
        ))

    reverse_shell_patterns = [
        r"/dev/tcp/", r"nc\s+.*\s-e\s", r"ncat\s+.*\s-e\s", r"bash\s+-i",
        r"python\w*\s+-c.*socket", r"powershell.*tcpclient", r"socat.*exec",
    ]
    if any(re.search(pattern, msg) for pattern in reverse_shell_patterns):
        _emit(alerts, _upsert_alert(
            db, event, "PROC-REVERSE-SHELL", {"message": event.message[:800]},
            f"{event.host}:{event.user or 'unknown'}",
        ))

    enum_markers = ["ffuf", "gobuster", "dirsearch", "nikto", "feroxbuster", "wfuzz"]
    if any(marker in msg or marker in raw for marker in enum_markers):
        _emit(alerts, _upsert_alert(
            db, event, "WEB-ENUM", {"src_ip": event.src_ip, "message": event.message[:500]},
            event.src_ip or event.host,
        ))

    if event.source == "suricata" and event.event_type == "alert" and event.severity == "high":
        signature = str((record.get("alert") or {}).get("signature_id") or event.message)
        _emit(alerts, _upsert_alert(
            db, event, "SURICATA-HIGH",
            {"src_ip": event.src_ip, "dst_ip": event.dst_ip, "signature": event.message},
            f"{event.src_ip or 'unknown'}:{signature}",
        ))

    if event.source == "windows" and event.event_type == "user_created":
        _emit(alerts, _upsert_alert(
            db, event, "WIN-ACCOUNT-CREATED", {"user": event.user, "host": event.host},
            f"{event.host}:{event.user or 'unknown'}",
        ))

    if event.source == "windows" and "powershell" in msg and re.search(r"\s-(enc|encodedcommand)\b", msg):
        _emit(alerts, _upsert_alert(
            db, event, "WIN-POWERSHELL-ENCODED",
            {"user": event.user, "message": event.message[:800]},
            f"{event.host}:{event.user or 'unknown'}",
        ))

    if event.source == "windows" and event.event_type == "audit_log_cleared":
        _emit(alerts, _upsert_alert(
            db, event, "WIN-LOG-CLEARED", {"host": event.host, "user": event.user}, event.host,
        ))

    cron_markers = ["/etc/crontab", "/etc/cron.", "crontab -e", "crontab -"]
    if event.source == "linux" and any(marker in msg for marker in cron_markers):
        _emit(alerts, _upsert_alert(
            db, event, "LINUX-PERSIST-CRON",
            {"host": event.host, "user": event.user, "message": event.message[:800]},
            f"{event.host}:{event.user or 'unknown'}",
        ))

    log_clear_patterns = [r"rm\s+(-\w+\s+)*(/var/log/|.*\.log)", r"truncate\s+.*(/var/log/|.*\.log)", r">\s*/var/log/"]
    if event.source == "linux" and any(re.search(pattern, msg) for pattern in log_clear_patterns):
        _emit(alerts, _upsert_alert(
            db, event, "LINUX-LOG-CLEARED",
            {"host": event.host, "user": event.user, "message": event.message[:800]}, event.host,
        ))

    return alerts
