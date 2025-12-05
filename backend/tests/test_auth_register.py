from fastapi.testclient import TestClient
from sqlmodel import Session

from backend.models.user import User


def test_register_user_success(client: TestClient):
    response = client.post(
        "/auth/register",
        json={"username": "testuser", "email": "test@example.com", "password": "Password123!"},
    )
    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_register_user_duplicate_username(client: TestClient, session: Session):
    # Create a user first
    existing_user = User(username="testuser", email="test1@example.com", hashed_password="somepassword")
    session.add(existing_user)
    session.commit()

    response = client.post(
        "/auth/register",
        json={"username": "testuser", "email": "test2@example.com", "password": "Password123!"},
    )
    assert response.status_code == 409
    assert response.json() == {"detail": "Username already registered"}


def test_register_user_duplicate_email(client: TestClient, session: Session):
    # Create a user first
    existing_user = User(username="testuser1", email="test@example.com", hashed_password="somepassword")
    session.add(existing_user)
    session.commit()

    response = client.post(
        "/auth/register",
        json={"username": "testuser2", "email": "test@example.com", "password": "Password123!"},
    )
    assert response.status_code == 409
    assert response.json() == {"detail": "Email already registered"}


def test_register_user_invalid_password(client: TestClient):
    response = client.post(
        "/auth/register",
        json={"username": "testuser", "email": "test@example.com", "password": "weak"},
    )
    assert response.status_code == 422 # Unprocessable Entity for validation errors from Pydantic
