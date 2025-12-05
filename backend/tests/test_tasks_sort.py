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


def test_sort_tasks_by_created_at_default(client: TestClient, session: Session):
    auth_headers = get_auth_header(client, username="sortuser1", email="sort1@example.com")
    user_response = client.post("/auth/login", json={"username": "sortuser1", "password": "Password123!"})
    user_id = user_response.json()["sub"]

    task1 = Task(title="Task C", user_id=uuid.UUID(user_id), created_at=datetime.utcnow() - timedelta(minutes=2))
    task2 = Task(title="Task B", user_id=uuid.UUID(user_id), created_at=datetime.utcnow() - timedelta(minutes=3))
    task3 = Task(title="Task A", user_id=uuid.UUID(user_id), created_at=datetime.utcnow() - timedelta(minutes=1))
    session.add(task1)
    session.add(task2)
    session.add(task3)
    session.commit()

    response = client.get("/tasks/", headers=auth_headers) # Default sort should be created_at descending
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3
    assert data[0]["title"] == "Task A" # Newest
    assert data[1]["title"] == "Task C"
    assert data[2]["title"] == "Task B" # Oldest


def test_sort_tasks_by_title_asc(client: TestClient, session: Session):
    auth_headers = get_auth_header(client, username="sortuser2", email="sort2@example.com")
    user_response = client.post("/auth/login", json={"username": "sortuser2", "password": "Password123!"})
    user_id = user_response.json()["sub"]

    task1 = Task(title="Task C", user_id=uuid.UUID(user_id))
    task2 = Task(title="Task B", user_id=uuid.UUID(user_id))
    task3 = Task(title="Task A", user_id=uuid.UUID(user_id))
    session.add(task1)
    session.add(task2)
    session.add(task3)
    session.commit()

    response = client.get("/tasks/?sort=title", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3
    assert data[0]["title"] == "Task A"
    assert data[1]["title"] == "Task B"
    assert data[2]["title"] == "Task C"


def test_sort_tasks_unauthenticated(client: TestClient):
    response = client.get("/tasks/?sort=title")
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials"}


def test_sort_tasks_invalid_criteria(client: TestClient, session: Session):
    auth_headers = get_auth_header(client, username="sortuser3", email="sort3@example.com")
    response = client.get("/tasks/?sort=invalid_criteria", headers=auth_headers)
    assert response.status_code == 422 # Pydantic validation error
