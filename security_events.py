from datetime import datetime, timezone


def create_security_event(
    event_type: str,
    status: str,
    message: str,
    source: int | None = None,
    target: int | None = None,
):
    return {
        "type": "security_event",
        "event": event_type,
        "status": status,
        "message": message,
        "source": source,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }