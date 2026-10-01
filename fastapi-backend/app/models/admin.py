from datetime import datetime, timezone

from pydantic import BaseModel, Field


class Admin(BaseModel):
    """
    Exactly one document should ever exist in the `admins` collection
    (enforced by a unique index on `username`). Created only via
    scripts/create_admin.py, run manually - never through any API route.
    """

    username: str
    password_hash: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
