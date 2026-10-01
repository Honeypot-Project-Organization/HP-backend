from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class SessionProtocol(str, Enum):
    ssh = "ssh"
    telnet = "telnet"


class SessionStatus(str, Enum):
    open = "open"
    closed = "closed"


class Session(BaseModel):
    """_id is Cowrie's own session identifier - re-ingesting the same
    session is a natural upsert on the same document."""

    id: str = Field(alias="_id")
    src_ip: str
    src_port: Optional[int] = None
    dst_port: int
    protocol: SessionProtocol
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    login_success: bool = False
    username: Optional[str] = None
    password: Optional[str] = None
    command_count: int = 0
    download_count: int = 0
    client_version: Optional[str] = None
    ttylog_ref: Optional[str] = None
    status: SessionStatus = SessionStatus.open

    model_config = {"populate_by_name": True}
