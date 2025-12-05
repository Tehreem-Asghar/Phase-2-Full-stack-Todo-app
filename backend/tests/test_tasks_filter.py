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


def test_filter_tasks_all_status(client: TestClient, session: Session):
    # Setup user and tasks with different statuses
    auth_headers = get_auth_header(client, username="filteruser1", email="filter1@example.com")
    user_response = client.post("/auth/login", json={"username": "filteruser1", "password": "Password123!"})
    user_id = user_response.json()["sub"]

    task1 = Task(title="Task Todo", user_id=uuid.UUID(user_id), status="todo")
    task2 = Task(title="Task In Progress", user_id=uuid.UUID(user_id), status="in-progress")
    task3 = Task(title="Task Completed", user_id=uuid.UUID(user_id), status="completed")
    session.add(task1)
    session.add(task2)
    session.add(task3)
    session.commit()

    response = client.get("/tasks/?filter=all", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3


def test_filter_tasks_todo_status(client: TestClient, session: Session):
    auth_headers = get_auth_header(client, username="filteruser2", email="filter2@example.com")
    user_response = client.post("/auth/login", json={"username": "filteruser2", "password": "Password123!"})
    user_id = user_response.json()["sub"]

    task1 = Task(title="Task A", user_id=uuid.UUID(user_id), status="todo")
    task2 = Task(title="Task B", user_id=uuid.UUID(user_id), status="in-progress")
    session.add(task1)
    session.add(task2)
    session.commit()

    response = client.get("/tasks/?filter=todo", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["title"] == "Task A"
    assert data[0]["status"] == "todo"


def test_filter_tasks_in_progress_status(client: TestClient, session: Session):
    auth_headers = get_auth_header(client, username="filteruser3", email="filter3@example.com")
    user_response = client.post("/auth/login", json={"username": "filteruser3", "password": "Password123!"})
    user_id = user_response.json()["sub"]

    task1 = Task(title="Task C", user_id=uuid.UUID(user_id), status="todo")
    task2 = Task(title="Task D", user_id=uuid.UUID(user_id), status="in-progress")
    session.add(task1)
    session.add(task2)
    session.commit()

    response = client.get("/tasks/?filter=in-progress", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["title"] == "Task D"
    assert data[0]["status"] == "in-progress"


def test_filter_tasks_completed_status(client: TestClient, session: Session):
    auth_headers = get_auth_header(client, username="filteruser4", email="filter4@example.com")
    user_response = client.post("/auth/login", json={"username": "filteruser4", "password": "Password123!"})
    user_id = user_response.json()["sub"]

    task1 = Task(title="Task E", user_id=uuid.UUID(user_id), status="completed")
    task2 = Task(title="Task F", user_id=uuid.UUID(user_id), status="in-progress")
    session.add(task1)
    session.add(task2)
    session.commit()

    response = client.get("/tasks/?filter=completed", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["title"] == "Task E"
    assert data[0]["status"] == "completed"


def test_filter_tasks_unauthenticated(client: TestClient):
    response = client.get("/tasks/?filter=all")
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials"}


def test_filter_tasks_invalid_status(client: TestClient, session: Session):
    auth_headers = get_auth_header(client, username="filteruser5", email="filter5@example.com")
    response = client.get("/tasks/?filter=invalid", headers=auth_headers)
    assert response.status_code == 422 # Pydantic validation error
