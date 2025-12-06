# Gemini CLI Rules - Backend

This `GEMINI.md` file provides specific guidelines and context for working with the backend of this project.

## Overview

The backend is a FastAPI application responsible for handling API requests related to user authentication and task management. It interacts with a PostgreSQL database using SQLModel as the ORM.

## Technology Stack

*   **Framework**: FastAPI
*   **ORM**: SQLModel (built on SQLAlchemy and Pydantic)
*   **Database**: PostgreSQL
*   **ASGI Server**: Uvicorn
*   **Authentication**: JWT (JSON Web Tokens) with `python-jose` and `passlib` for password hashing.
*   **Dependency Management**: `pyproject.toml` (Poetry) and `requirements.txt`

## Setup

1.  **Environment Variables**:
    Create a `.env` file in the `backend` directory based on `.env.example` (if available, otherwise refer to `database.py` for expected variables like `DATABASE_URL`).
    Example `.env` content:
    ```
    DATABASE_URL="postgresql://user:password@localhost:5432/todoapp"
    SECRET_KEY="YOUR_SECRET_KEY"
    ALGORITHM="HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES=30
    ```

2.  **Install Dependencies**:
    It's recommended to use a virtual environment.
    ```bash
    cd backend
    python -m venv .venv
    ./.venv/Scripts/activate # On Windows
    # source .venv/bin/activate # On macOS/Linux
    pip install -r requirements.txt
    ```
    If `poetry` is used, install dependencies via `poetry install`.

3.  **Database Migration**:
    The database tables are automatically created on application startup if they don't exist, as handled by `create_db_and_tables()` in `database.py` and called in `app.py`'s `on_startup` event.

## Running the Application

To start the FastAPI development server:

```bash
cd backend
uvicorn app:app --reload --host 0.0.0.0 --port 8000
```
The API documentation will be available at `http://localhost:8000/docs`.

## Testing

Backend tests are located in the `backend/tests/` directory.

To run the tests:

```bash
cd backend
pytest
```
Ensure you have `pytest` installed (`pip install pytest`).