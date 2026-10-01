from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class RawEvent(BaseModel):
    """Copy of every Cowrie log line (keys sanitized) - audit trail / reprocessing
    safety net. _id is a SHA-256 of the event's content, which makes resends
    idempotent. Expires after RAW_EVENT_RETENTION_DAYS via a TTL index."""

    id: str = Field(alias="_id")
    session_id: Optional[str] = None
    eventid: str
    received_at: datetime
    raw: Dict[str, Any]

    model_config = {"populate_by_name": True}
