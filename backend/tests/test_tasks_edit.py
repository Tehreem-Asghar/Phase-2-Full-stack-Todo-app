from fastapi.testclient import TestClient
from sqlmodel import Session, select
import uuid
from datetime import datetime, timedelta

from backend.models.user import User
from backend.models.task import Task
from backend.security import get_password_hash


def get_auth_header(client: TestClient, username: str = "testuser", email: str = "test@example.com", password: str = "Password123!"):
    # Attempt to register the user, ignoring conflicts if they already exist from previous tests
    client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    # Then login
    response = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_edit_task_success(client: TestClient, session: Session):
    # Setup user and task
    auth_headers = get_auth_header(client, username="edituser", email="edit@example.com")
    user_response = client.post("/auth/login", json={"username": "edituser", "password": "Password123!"})
    user_id = user_response.json()["sub"]

    task_initial = Task(title="Original Title", description="Original description", user_id=uuid.UUID(user_id))
    session.add(task_initial)
    session.commit()
    session.refresh(task_initial)

    initial_updated_at = task_initial.updated_at

    # Update task title and description
    response = client.put(
        f"/tasks/{task_initial.id}",
        json={"title": "New Title", "description": "New description"},
        headers=auth_headers,
    )
    assert response.status_code == 200
    updated_task = response.json()
    assert updated_task["title"] == "New Title"
    assert updated_task["description"] == "New description"
    assert updated_task["id"] == str(task_initial.id)
    assert updated_task["user_id"] == str(user_id)
    assert datetime.fromisoformat(updated_task["updated_at"].replace("Z", "+00:00")) > initial_updated_at


def test_edit_task_not_owned(client: TestClient, session: Session):
    # User 1 creates a task
    user1_password_hash = get_password_hash("Password123!")
    user1 = User(username="editowner", email="editowner@example.com", hashed_password=user1_password_hash)
    session.add(user1)
    session.commit()
    session.refresh(user1)
    task = Task(title="Owner's task to edit", user_id=user1.id)
    session.add(task)
    session.commit()
    session.refresh(task)

    # User 2 tries to update User 1's task
    auth_headers_user2 = get_auth_header(client, username="editintruder", email="editintruder@example.com")
    response = client.put(
        f"/tasks/{task.id}",
        json={"title": "Tried to change"},
        headers=auth_headers_user2,
    )
    assert response.status_code == 403 # Forbidden
    assert response.json() == {"detail": "Not authorized to update this task"}


def test_edit_task_invalid_title(client: TestClient, session: Session):
    # Setup user and task
    auth_headers = get_auth_header(client, username="invalidtitleuser", email="invalidtitle@example.com")
    user_response = client.post("/auth/login", json={"username": "invalidtitleuser", "password": "Password123!"})
    user_id = user_response.json()["sub"]
    task = Task(title="Valid Title", user_id=uuid.UUID(user_id))
    session.add(task)
    session.commit()
    session.refresh(task)

    response = client.put(
        f"/tasks/{task.id}",
        json={"title": ""}, # Empty title
        headers=auth_headers,
    )
    assert response.status_code == 422 # Pydantic validation error for min_length=1

