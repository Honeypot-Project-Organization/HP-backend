from datetime import datetime
from typing import Annotated, Optional

from pydantic import BaseModel, BeforeValidator, Field

PyObjectId = Annotated[str, BeforeValidator(str)]


class Download(BaseModel):
    id: Optional[PyObjectId] = Field(default=None, alias="_id")
    session_id: str
    src_ip: str
    timestamp: datetime
    url: Optional[str] = None
    filename: Optional[str] = None
    sha256: str
    size_bytes: Optional[int] = None

    model_config = {"populate_by_name": True}
