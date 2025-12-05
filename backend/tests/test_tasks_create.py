from fastapi.testclient import TestClient
from sqlmodel import Session

from backend.models.user import User
from backend.security import get_password_hash


def get_auth_header(client: TestClient, username: str = "testuser", password: str = "Password123!"):
    # Register user first for authentication
    client.post(
        "/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": password},
    )
    # Then login
    response = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_create_task_success(client: TestClient, session: Session):
    headers = get_auth_header(client)
    response = client.post(
        "/tasks/",
        json={"title": "Test Task", "description": "This is a test description"},
        headers=headers,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "Test Task"
    assert data["description"] == "This is a test description"
    assert data["status"] == "todo"
    assert "id" in data
    assert "user_id" in data


def test_create_task_unauthenticated(client: TestClient):
    response = client.post(
        "/tasks/",
        json={"title": "Test Task", "description": "This is a test description"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}


def test_create_task_invalid_data(client: TestClient, session: Session):
    headers = get_auth_header(client)
    response = client.post(
        "/tasks/",
        json={"title": "", "description": "This is a test description"},
        headers=headers,
    )
    assert response.status_code == 422 # Pydantic validation error for min_length=1
