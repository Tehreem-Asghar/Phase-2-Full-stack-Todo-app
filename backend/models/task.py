import uuid
from datetime import datetime
from typing import Optional

from sqlmodel import Field, Relationship, SQLModel

# Import the User model from the same directory
from .user import User


class Task(SQLModel, table=True):
    id: Optional[uuid.UUID] = Field(default_factory=uuid.uuid4, primary_key=True, index=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    title: str = Field(max_length=255)
    description: Optional[str] = Field(default=None)
    status: str = Field(default="todo", max_length=20) # ENUM: "todo", "in-progress", "completed"
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    updated_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"onupdate": datetime.utcnow}, nullable=False)

    user: Optional[User] = Relationship(back_populates="tasks")
