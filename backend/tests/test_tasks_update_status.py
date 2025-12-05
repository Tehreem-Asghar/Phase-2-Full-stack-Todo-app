from fastapi.testclient import TestClient
from sqlmodel import Session, select
import uuid
from datetime import datetime, timedelta

from backend.models.user import User
from backend.models.task import Task
from backend.security import get_password_hash


def get_auth_header(client: TestClient, username: str = "testuser", email: str = "test@example.com", password: str = "Password123!"):
    # Register user first for authentication
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


def test_update_task_status_success(client: TestClient, session: Session):
    # Setup user and task
    auth_headers = get_auth_header(client, username="statususer", email="status@example.com")
    user_response = client.post("/auth/login", json={"username": "statususer", "password": "Password123!"})
    user_id = user_response.json()["sub"] # Assuming sub is user ID

    task_initial = Task(title="Update me", user_id=uuid.UUID(user_id), status="todo")
    session.add(task_initial)
    session.commit()
    session.refresh(task_initial)

    initial_updated_at = task_initial.updated_at

    # Update task status
    response = client.put(
        f"/tasks/{task_initial.id}",
        json={"status": "completed"},
        headers=auth_headers,
    )
    assert response.status_code == 200
    updated_task = response.json()
    assert updated_task["status"] == "completed"
    assert updated_task["id"] == str(task_initial.id)
    assert updated_task["user_id"] == str(user_id)
    # Check if updated_at has changed
    assert datetime.fromisoformat(updated_task["updated_at"].replace("Z", "+00:00")) > initial_updated_at


def test_update_task_status_unauthenticated(client: TestClient, session: Session):
    # Setup user and task for a dummy task
    user_password_hash = get_password_hash("Password123!")
    user = User(username="unauthuser", email="unauth@example.com", hashed_password=user_password_hash)
    session.add(user)
    session.commit()
    session.refresh(user)
    task = Task(title="Unauth task", user_id=user.id)
    session.add(task)
    session.commit()
    session.refresh(task)

    response = client.put(
        f"/tasks/{task.id}",
        json={"status": "completed"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials"}


def test_update_task_status_not_owned(client: TestClient, session: Session):
    # User 1 creates a task
    user1_password_hash = get_password_hash("Password123!")
    user1 = User(username="owneruser", email="owner@example.com", hashed_password=user1_password_hash)
    session.add(user1)
    session.commit()
    session.refresh(user1)
    task = Task(title="Owner's task", user_id=user1.id)
    session.add(task)
    session.commit()
    session.refresh(task)

    # User 2 tries to update User 1's task
    auth_headers_user2 = get_auth_header(client, username="intruder", email="intruder@example.com")
    response = client.put(
        f"/tasks/{task.id}",
        json={"status": "completed"},
        headers=auth_headers_user2,
    )
    assert response.status_code == 404 # Or 403 Forbidden, depending on implementation
    assert response.json() == {"detail": "Task not found"} # Assuming a generic not found for security


def test_update_task_status_invalid_value(client: TestClient, session: Session):
    # Setup user and task
    auth_headers = get_auth_header(client, username="invalidstatususer", email="invalidstatus@example.com")
    user_response = client.post("/auth/login", json={"username": "invalidstatususer", "password": "Password123!"})
    user_id = user_response.json()["sub"]
    task = Task(title="Invalid status", user_id=uuid.UUID(user_id), status="todo")
    session.add(task)
    session.commit()
    session.refresh(task)

    response = client.put(
        f"/tasks/{task.id}",
        json={"status": "invalid_status"},
        headers=auth_headers,
    )
    assert response.status_code == 422 # Pydantic validation error for enum
