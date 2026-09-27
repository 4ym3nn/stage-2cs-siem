from datetime import datetime, timezone
from typing import Any
from .schemas import EventIn


def _ts(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def normalize_suricata(record: dict[str, Any]) -> EventIn:
    etype = record.get("event_type", "suricata")
    alert = record.get("alert") or {}
    sev_num = alert.get("severity")
    severity = "high" if sev_num == 1 else "medium" if sev_num == 2 else "low" if sev_num == 3 else "info"
    message = alert.get("signature") or record.get("app_proto") or etype
    return EventIn(
        timestamp=_ts(record.get("timestamp")),
        source="suricata",
        host=record.get("host") or record.get("in_iface") or "sensor",
        event_type=etype,
        severity=severity,
        src_ip=record.get("src_ip"),
        dst_ip=record.get("dest_ip"),
        user=None,
        message=str(message),
        raw=record,
    )


def normalize_linux(record: dict[str, Any]) -> EventIn:
    msg = str(record.get("message") or record.get("msg") or "")
    return EventIn(
        timestamp=_ts(record.get("timestamp")),
        source="linux",
        host=str(record.get("host") or record.get("hostname") or "linux-host"),
        event_type=str(record.get("event_type") or "auth"),
        severity=str(record.get("severity") or "info"),
        src_ip=record.get("src_ip") or record.get("ip"),
        dst_ip=record.get("dst_ip"),
        user=record.get("user") or record.get("username"),
        message=msg,
        raw=record,
    )


def normalize_windows(record: dict[str, Any]) -> EventIn:
    event_id = str(record.get("event_id") or record.get("EventID") or "")
    msg = str(record.get("message") or record.get("Message") or "")
    etype = {
        "4625": "failed_logon",
        "4624": "logon",
        "4720": "user_created",
        "4732": "group_member_added",
        "4688": "process_create",
        "1102": "audit_log_cleared",
    }.get(event_id, f"windows_{event_id}" if event_id else "windows_event")
    return EventIn(
        timestamp=_ts(record.get("timestamp") or record.get("TimeCreated")),
        source="windows",
        host=str(record.get("host") or record.get("Computer") or "windows-host"),
        event_type=etype,
        severity=str(record.get("severity") or "info"),
        src_ip=record.get("src_ip") or record.get("IpAddress"),
        dst_ip=record.get("dst_ip"),
        user=record.get("user") or record.get("TargetUserName"),
        message=msg,
        raw=record,
    )
