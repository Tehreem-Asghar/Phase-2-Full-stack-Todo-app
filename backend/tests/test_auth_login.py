from fastapi.testclient import TestClient
from sqlmodel import Session

from backend.models.user import User
from backend.security import get_password_hash


def test_login_user_success(client: TestClient, session: Session):
    # Register a user first
    hashed_password = get_password_hash("Password123!")
    user = User(username="loginuser", email="login@example.com", hashed_password=hashed_password)
    session.add(user)
    session.commit()
    session.refresh(user)

    response = client.post(
        "/auth/login",
        json={"username": "loginuser", "password": "Password123!"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_user_incorrect_username(client: TestClient):
    response = client.post(
        "/auth/login",
        json={"username": "nonexistent", "password": "Password123!"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Incorrect username or password"}


def test_login_user_incorrect_password(client: TestClient, session: Session):
    # Register a user first
    hashed_password = get_password_hash("CorrectPassword123!")
    user = User(username="wrongpassuser", email="wrongpass@example.com", hashed_password=hashed_password)
    session.add(user)
    session.commit()
    session.refresh(user)

    response = client.post(
        "/auth/login",
        json={"username": "wrongpassuser", "password": "WrongPassword!"},
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Incorrect username or password"}
