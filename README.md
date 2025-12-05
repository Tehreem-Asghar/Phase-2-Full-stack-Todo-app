# hackathon-todo: Phase II - Full-Stack Todo Web Application

This repository contains the Phase II implementation of a full-stack Todo web application, built using Spec-Kit and AI-driven development tools. It evolves from a Python console application to a multi-user web application with a modern technology stack.

## Project Evolution

- **Phase I**: Python Console Todo App (in-memory)
- **Phase II**: Full-Stack Multi-User Web Application (Next.js + FastAPI + PostgreSQL)

## Architecture

This project follows a monorepo structure, strictly defined in the project's constitution (`.specify/memory/constitution.md`).

- **Frontend**: Next.js 16+ (App Router)
- **Backend**: Python FastAPI with SQLModel ORM
- **Database**: PostgreSQL (Neon Serverless recommended for cloud)
- **Authentication**: Better Auth (frontend) issuing JWTs, verified by backend.

## Monorepo Structure

```
hackathon-todo/
  ├── .spec-kit/              # Spec-Kit configuration
  ├── specs/                  # Feature specifications, architecture, API, DB schema, UI
  ├── frontend/               # Next.js application
  ├── backend/                # FastAPI application
  ├── docker-compose.yml      # Local development environment setup
  ├── GEMINI.md               # Root project rules
  └── README.md               # This file
```

## Technology Stack

### Frontend
- **Framework**: Next.js 16+ (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **Authentication**: Better Auth for login/signup, JWT tokens stored securely
- **API Client**: `/frontend/lib/api.ts`

### Backend
- **Framework**: Python FastAPI
- **ORM**: SQLModel
- **Database**: Neon Serverless PostgreSQL (or any PostgreSQL compatible)
- **Authentication**: JWT verification from Better Auth token, shared secret `BETTER_AUTH_SECRET`
- **API Routes**: All under `/api/`, filtered by authenticated user's `user_id`

### Database
- `tasks` table
- `users` table (managed by Better Auth)
- Schema defined in `/specs/database/schema.md`

### API Requirements
- Defined in `/specs/api/rest-endpoints.md`
- Endpoints for CRUD operations on tasks, including `PATCH /api/{user_id}/tasks/{id}/complete`
- All endpoints **MUST**: Validate JWT, extract `user_id` from token, ensure ownership of tasks.

### UI Requirements
- Defined in `/specs/ui/*`
- Login / Signup pages
- Dashboard (tasks list)
- Task CRUD UI
- Responsive design

## Prerequisites

- Docker and Docker Compose (for local development)
- Python 3.10+ (for backend development outside Docker, if preferred)
- Node.js 18+ (for frontend development outside Docker, if preferred)

## Quickstart Guide

This guide provides instructions to quickly set up and run the Full-Stack Todo Web Application.

### Prerequisites

Before you begin, ensure you have the following installed:

-   **Docker Desktop**: For running PostgreSQL and managing containers.
-   **Python 3.11+**: For the FastAPI backend.
-   **Node.js 18+ and npm/yarn/pnpm**: For the Next.js frontend.
-   **Git**: For cloning the repository.

### 1. Clone the Repository

First, clone the project repository to your local machine:

```bash
git clone <repository-url>
cd Phase-II-Todo-Full-Stack-Web-Application
```

### 2. Set Up the Backend (FastAPI)

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
    ```

4.  **Database Setup (Docker Compose)**:
    Ensure Docker Desktop is running. From the project root directory, bring up the database using Docker Compose:
    ```bash
    docker-compose up -d postgres
    ```
    *(Note: `docker-compose.yml` will be created during implementation phase)*

5.  **Environment Variables**:
    Create a `.env` file in the project root based on `.env.example` (which will be created in T004).
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
    The backend API will be accessible at `http://localhost:8000`.

### 3. Set Up the Frontend (Next.js)

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
    -   `NEXT_PUBLIC_BACKEND_URL="http://localhost:8000"`

4.  **Run the Next.js application**:
    ```bash
    npm run dev
    ```
    The frontend application will be accessible at `http://localhost:3000`.

### 4. Using the Application

-   Open your browser to `http://localhost:3000`.
-   Register a new user account.
-   Log in with your new credentials.
-   Start creating and managing your todo tasks!

### Troubleshooting

-   **Database connection issues**: Ensure Docker is running and the `DATABASE_URL` in your backend's `.env` file is correct.
-   **Backend not starting**: Check if port 8000 is already in use. Ensure all Python dependencies are installed.
-   **Frontend not starting**: Check if port 3000 is already in use. Ensure all Node.js dependencies are installed.
-   **JWT errors**: Verify that `SECRET_KEY` and `ALGORITHM` are correctly configured in the project root's `.env` file.

## Development Guidelines

- All development must adhere to the principles outlined in `.specify/memory/constitution.md`.
- Features are driven by specifications in the `specs/` directory.
- Layered `GEMINI.md` files provide specific guidelines for `frontend` and `backend` development.

## Contributing

Please refer to the project's constitution and specifications for guidelines on contributing.

## License

[Your License Information Here]