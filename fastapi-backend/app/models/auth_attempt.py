from datetime import datetime
from typing import Annotated, Optional

from pydantic import BaseModel, BeforeValidator, Field

PyObjectId = Annotated[str, BeforeValidator(str)]


class AuthAttempt(BaseModel):
    id: Optional[PyObjectId] = Field(default=None, alias="_id")
    session_id: str
    src_ip: str
    username: str
    password: str
    success: bool
    timestamp: datetime

    model_config = {"populate_by_name": True}
