from datetime import datetime

from pydantic import BaseModel, Field


class IPIntel(BaseModel):
    """_id is the IP address itself - updates are a natural upsert."""

    id: str = Field(alias="_id")
    first_seen: datetime
    last_seen: datetime
    total_sessions: int = 0
    total_commands: int = 0
    total_auth_attempts: int = 0
    successful_logins: int = 0
    threat_score: float = 0.0
    updated_at: datetime

    model_config = {"populate_by_name": True}
