# Quickstart Guide: Full-Stack Todo Web Application

This guide provides instructions to quickly set up and run the Full-Stack Todo Web Application.

## Prerequisites

Before you begin, ensure you have the following installed:

-   **Docker Desktop**: For running PostgreSQL and managing containers.
-   **Python 3.11+**: For the FastAPI backend.
-   **Node.js 18+ and npm/yarn/pnpm**: For the Next.js frontend.
-   **Git**: For cloning the repository.

## 1. Clone the Repository

First, clone the project repository to your local machine:

```bash
git clone <repository-url>
cd Phase-II-Todo-Full-Stack-Web-Application
```

## 2. Set Up the Backend (FastAPI)

1.  **Navigate to the backend directory**:
    ```bash
    cd backend
    ```

2.  **Create a Python virtual environment and activate it**:
    ```bash
    python -m venv .venv
    # On Windows
    .venv\Scripts\activate
    # On macOS/Linux
    source .venv/bin/activate
    ```

3.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt # (assuming requirements.txt will be generated)
    # Or manually install:
    # pip install fastapi uvicorn sqlmodel python-jose[cryptography] passlib[bcrypt] psycopg2-binary # or psycopg
    ```

4.  **Database Setup (Docker Compose)**:
    Ensure Docker Desktop is running. From the project root directory (D:\Hackhathon 2\hk\project_2\Phase-II-Todo-Full-Stack-Web-Application), bring up the database using Docker Compose:
    ```bash
    docker-compose up -d postgres
    ```
    *(Note: `docker-compose.yml` will be created during implementation phase)*

5.  **Environment Variables**:
    Create a `.env` file in the `backend/` directory based on a `.env.example` (to be provided).
    Key variables will include:
    -   `DATABASE_URL="postgresql://user:password@localhost:5432/dbname"`
    -   `SECRET_KEY="your-super-secret-jwt-key"` (for JWT encoding/decoding)
    -   `ALGORITHM="HS256"` (for JWT)

6.  **Run Database Migrations (if applicable)**:
    *(Details to be provided during implementation)*

7.  **Run the FastAPI application**:
    ```bash
    uvicorn app.main:app --reload
    ```
    The backend API will be accessible at `http://localhost:8000/api`.

## 3. Set Up the Frontend (Next.js)

1.  **Navigate to the frontend directory**:
    ```bash
    cd frontend
    ```

2.  **Install dependencies**:
    ```bash
    npm install
    # or yarn install
    # or pnpm install
    ```

3.  **Environment Variables**:
    Create a `.env.local` file in the `frontend/` directory.
    Key variables will include:
    -   `${process.env.NEXT_PUBLIC_BACKEND_URL}="http://localhost:8000/api"

4.  **Run the Next.js application**:
    ```bash
    npm run dev
    ```
    The frontend application will be accessible at `http://localhost:3000`.

## 4. Using the Application

-   Open your browser to `http://localhost:3000`.
-   Register a new user account.
-   Log in with your new credentials.
-   Start creating and managing your todo tasks!

## Troubleshooting

-   **Database connection issues**: Ensure Docker is running and the `DATABASE_URL` in your backend's `.env` file is correct.
-   **Backend not starting**: Check if port 8000 is already in use. Ensure all Python dependencies are installed.
-   **Frontend not starting**: Check if port 3000 is already in use. Ensure all Node.js dependencies are installed.
-   **JWT errors**: Verify that `SECRET_KEY` and `ALGORITHM` are correctly configured in the backend's `.env` file.
