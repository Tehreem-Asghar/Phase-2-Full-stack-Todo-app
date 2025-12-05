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


def test_delete_task_success(client: TestClient, session: Session):
    # Setup user and task
    auth_headers = get_auth_header(client, username="deleteuser", email="delete@example.com")
    user_response = client.post("/auth/login", json={"username": "deleteuser", "password": "Password123!"})
    user_id = user_response.json()["sub"]

    task_to_delete = Task(title="Task to Delete", user_id=uuid.UUID(user_id))
    session.add(task_to_delete)
    session.commit()
    session.refresh(task_to_delete)

    # Delete the task
    response = client.delete(
        f"/tasks/{task_to_delete.id}",
        headers=auth_headers,
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Task deleted successfully"}

    # Verify task is deleted from DB
    deleted_task = session.exec(select(Task).where(Task.id == task_to_delete.id)).first()
    assert deleted_task is None


def test_delete_task_unauthenticated(client: TestClient, session: Session):
    # Setup a dummy task
    user_password_hash = get_password_hash("Password123!")
    user = User(username="unauthdelete", email="unauthdelete@example.com", hashed_password=user_password_hash)
    session.add(user)
    session.commit()
    session.refresh(user)
    task = Task(title="Unauth Task", user_id=user.id)
    session.add(task)
    session.commit()
    session.refresh(task)

    response = client.delete(
        f"/tasks/{task.id}",
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials"}


def test_delete_task_not_owned(client: TestClient, session: Session):
    # User 1 creates a task
    user1_password_hash = get_password_hash("Password123!")
    user1 = User(username="ownerdelete", email="ownerdelete@example.com", hashed_password=user1_password_hash)
    session.add(user1)
    session.commit()
    session.refresh(user1)
    task = Task(title="Owner's task to delete", user_id=user1.id)
    session.add(task)
    session.commit()
    session.refresh(task)

    # User 2 tries to delete User 1's task
    auth_headers_user2 = get_auth_header(client, username="intruderdelete", email="intruderdelete@example.com")
    response = client.delete(
        f"/tasks/{task.id}",
        headers=auth_headers_user2,
    )
    assert response.status_code == 404 # Or 403 Forbidden, depending on implementation
    assert response.json() == {"detail": "Task not found"} # Assuming a generic not found for security


def test_delete_task_non_existent(client: TestClient, session: Session):
    auth_headers = get_auth_header(client, username="nonexistenttaskuser", email="nonexistenttask@example.com")
    
    non_existent_id = uuid.uuid4()
    response = client.delete(
        f"/tasks/{non_existent_id}",
        headers=auth_headers,
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "Task not found"}

