# Data Model: Full-Stack Todo Web Application

## Entities

### User

**Description**: Represents a user of the application. Managed primarily by Better Auth on the frontend, with backend interactions for JWT verification.

**Fields**:
- `id` (VARCHAR(36), PRIMARY KEY, Auto-generated UUID)
- `username` (VARCHAR(20), UNIQUE, NOT NULL, Alphanumeric, 3-20 characters)
- `email` (VARCHAR(255), UNIQUE, NOT NULL, Valid email format)
- `hashed_password` (VARCHAR(255), NOT NULL, Stores securely hashed password)
- `created_at` (TIMESTAMP, NOT NULL, DEFAULT CURRENT_TIMESTAMP)
- `updated_at` (TIMESTAMP, NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)

**Relationships**:
- One-to-many with `Task` (a user can have multiple tasks).

**Validation Rules**:
- **Username**: Must be unique, alphanumeric, and between 3 and 20 characters.
- **Email**: Must be unique and a valid email format.
- **Password**: At least 8 characters, containing at least one uppercase letter, one lowercase letter, one number, and one special character.

---

### Task

**Description**: Represents a single todo item created by a user.

**Fields**:
- `id` (VARCHAR(36), PRIMARY KEY, Auto-generated UUID)
- `user_id` (VARCHAR(36), FOREIGN KEY to `users.id`, NOT NULL, Links task to its owner)
- `title` (VARCHAR(255), NOT NULL, 1-255 characters)
- `description` (TEXT, Optional)
- `status` (VARCHAR(20), NOT NULL, DEFAULT 'todo', ENUM: 'todo', 'in-progress', 'completed')
- `created_at` (TIMESTAMP, NOT NULL, DEFAULT CURRENT_TIMESTAMP)
- `updated_at` (TIMESTAMP, NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)

**Relationships**:
- Many-to-one with `User` (many tasks belong to one user).

**Validation Rules**:
- **Title**: Must be between 1 and 255 characters.
- **Status**: Must be one of 'todo', 'in-progress', or 'completed'.
- **Ownership**: A task can only be viewed, updated, or deleted by its `user_id`.

**State Transitions**:
- `todo` -> `in-progress`
- `todo` -> `completed`
- `in-progress` -> `todo`
- `in-progress` -> `completed`
- `completed` -> `todo` (or `in-progress`) - *Flexible for user to reopen a completed task.*

---

## Database Schema (SQLModel Representation)

The following outlines the expected SQLModel definitions for the `User` and `Task` entities, reflecting the above data model.

```python
# backend/models/user.py
import uuid
from datetime import datetime
from typing import List, Optional

from sqlmodel import Field, Relationship, SQLModel


class User(SQLModel, table=True):
    id: Optional[uuid.UUID] = Field(default_factory=uuid.uuid4, primary_key=True, index=True)
    username: str = Field(unique=True, max_length=20, index=True)
    email: str = Field(unique=True, max_length=255, index=True)
    hashed_password: str = Field(max_length=255)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    updated_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"onupdate": datetime.utcnow}, nullable=False)

    tasks: List["Task"] = Relationship(back_populates="user")


# backend/models/task.py
import uuid
from datetime import datetime
from typing import Optional

from sqlmodel import Field, Relationship, SQLModel

class Task(SQLModel, table=True):
    id: Optional[uuid.UUID] = Field(default_factory=uuid.uuid4, primary_key=True, index=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    title: str = Field(max_length=255)
    description: Optional[str] = Field(default=None, sa_column_kwargs={"type": "TEXT"})
    status: str = Field(default="todo", max_length=20) # ENUM: "todo", "in-progress", "completed"
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    updated_at: datetime = Field(default_factory=datetime.utcnow, sa_column_kwargs={"onupdate": datetime.utcnow}, nullable=False)

    user: Optional[User] = Relationship(back_populates="tasks")

# Note: The `status` field will be enforced as an ENUM or checked programmatically
# in the backend to ensure only allowed values are set.
# The UUID fields will be handled by SQLModel's default_factory.
