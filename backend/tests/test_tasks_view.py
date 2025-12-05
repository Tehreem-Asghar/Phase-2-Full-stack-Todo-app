from fastapi.testclient import TestClient
from sqlmodel import Session, select
import uuid

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


def test_get_tasks_success(client: TestClient, session: Session):
    # Create a user
    user_password_hash = get_password_hash("Password123!")
    user = User(username="viewuser", email="view@example.com", hashed_password=user_password_hash)
    session.add(user)
    session.commit()
    session.refresh(user)

    # Create tasks for this user
    task1 = Task(title="User1 Task 1", user_id=user.id)
    task2 = Task(title="User1 Task 2", user_id=user.id)
    session.add(task1)
    session.add(task2)
    session.commit()
    session.refresh(task1)
    session.refresh(task2)

    headers = get_auth_header(client, username="viewuser", email="view@example.com")
    response = client.get("/tasks/", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    assert data[0]["title"] == "User1 Task 1"
    assert data[1]["title"] == "User1 Task 2"


def test_get_tasks_unauthenticated(client: TestClient):
    response = client.get("/tasks/")
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials"}


def test_get_tasks_only_own_tasks(client: TestClient, session: Session):
    # Create User 1 and their tasks
    user1_password_hash = get_password_hash("Password123!")
    user1 = User(username="viewuser1", email="view1@example.com", hashed_password=user1_password_hash)
    session.add(user1)
    session.commit()
    session.refresh(user1)

    task1_user1 = Task(title="User1 Task A", user_id=user1.id)
    task2_user1 = Task(title="User1 Task B", user_id=user1.id)
    session.add(task1_user1)
    session.add(task2_user1)
    session.commit()
    session.refresh(task1_user1)
    session.refresh(task2_user1)

    # Create User 2 and their tasks
    user2_password_hash = get_password_hash("Password123!")
    user2 = User(username="viewuser2", email="view2@example.com", hashed_password=user2_password_hash)
    session.add(user2)
    session.commit()
    session.refresh(user2)

    task1_user2 = Task(title="User2 Task X", user_id=user2.id)
    session.add(task1_user2)
    session.commit()
    session.refresh(task1_user2)

    # User 1 requests tasks
    headers_user1 = get_auth_header(client, username="viewuser1", email="view1@example.com")
    response_user1 = client.get("/tasks/", headers=headers_user1)
    assert response_user1.status_code == 200
    data_user1 = response_user1.json()
    assert len(data_user1) == 2
    assert data_user1[0]["title"] == "User1 Task A"
    assert data_user1[1]["title"] == "User1 Task B"

    # User 2 requests tasks
    headers_user2 = get_auth_header(client, username="viewuser2", email="view2@example.com")
    response_user2 = client.get("/tasks/", headers=headers_user2)
    assert response_user2.status_code == 200
    data_user2 = response_user2.json()
    assert len(data_user2) == 1
    assert data_user2[0]["title"] == "User2 Task X"

