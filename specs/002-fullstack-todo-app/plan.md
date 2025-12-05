# Implementation Plan: Full-Stack Todo Web Application

**Branch**: `002-fullstack-todo-app` | **Date**: 2025-12-04 | **Spec**: D:\Hackhathon 2\hk\project_2\Phase-II-Todo-Full-Stack-Web-Application\specs\002-fullstack-todo-app\spec.md
**Input**: Feature specification from `/specs/[###-feature-name]/spec.md`

**Note**: This template is filled in by the `/sp.plan` command. See `.specify/templates/commands/plan.md` for the execution workflow.

## Summary

This plan outlines the technical implementation for the "Full-Stack Todo Web Application". The application will enable users to register, log in, and manage their personal todo tasks. Key functionalities include user authentication (registration, login, logout), comprehensive CRUD operations for tasks, and advanced filtering and sorting capabilities. The technical architecture adheres to a spec-driven monorepo approach, utilizing Next.js for the frontend, FastAPI with SQLModel for the backend, and Neon Serverless PostgreSQL for data persistence. JWT-based authentication will secure API interactions.

## Technical Context

<!--
  ACTION REQUIRED: Replace the content in this section with the technical details
  for the project. The structure here is presented in advisory capacity to guide
  the iteration process.
-->

**Language/Version**: Python 3.11+ (Backend), TypeScript (Frontend). Specific versions: Next.js v16.0.6, FastAPI v0.123.5.
**Primary Dependencies**: Next.js (App Router), FastAPI, SQLModel ORM, Tailwind CSS, Better Auth (Frontend), `python-jose` (for JWT handling), `passlib` (for password hashing), `psycopg` (PostgreSQL driver).
**Storage**: Neon Serverless PostgreSQL.
**Testing**: `pytest` (Backend), `Jest` / `React Testing Library` (Frontend), `Playwright` (E2E testing).
**Target Platform**: Web (Browser-based Frontend, Serverless/Containerized Backend).
**Project Type**: Monorepo with `frontend/Next.js app` and `backend/FastAPI app`.
**Performance Goals**: Support for up to 1,000 concurrent users and 200 tasks per user with acceptable response times (e.g., p95 latency < 500ms for CRUD operations).
**Constraints**:
- Adherence to GDPR/CCPA regulations for user data retention (1 year max after account deletion, 1 year max for task data after deletion).
- Secure password hashing and storage.
- JWT-based authentication for all protected routes, with basic user ID in JWT payload.
- All API routes under `/api/`.
- All queries must be filtered by the authenticated user's `user_id`.
- Frontend protected routes redirect to `/login` if unauthenticated or JWT expired.
- Backend JWT validation on every protected request.
**Scale/Scope**: 1,000 users, 200 tasks per user.


## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

The project's feature specification (`spec.md`) and overall plan align well with the established `.specify/memory/constitution.md`.

-   **Monorepo Structure**: Fully aligned. The project setup mandates `frontend/Next.js app` and `backend/FastAPI app` within the monorepo, as specified.
-   **Development Principles**: Adhering to Spec-First Development, Layered GEMINI.md files, Monorepo as Single Source of Truth, and AI Implementation Rules.
-   **Technology Stack Requirements**: All specified technologies (Next.js, TypeScript, Tailwind CSS, Better Auth, FastAPI, SQLModel, Neon Serverless PostgreSQL, JWT) are aligned with the constitution.
-   **Database**: The proposed `users` and `tasks` tables, along with schema definition in `/specs/database/schema.md`, are in full alignment.
-   **Authentication**: The plan for Better Auth for JWT issuance and backend verification with `BETTER_AUTH_SECRET` is aligned.
-   **API Requirements**: The constitution specifies API routes with explicit `user_id` in the path (e.g., `/api/{user_id}/tasks`), while the feature spec defines them more generically (e.g., `/api/tasks`), expecting the `user_id` to be extracted from the JWT. This is a deliberate design decision to simplify the API surface and improve security by not exposing `user_id` directly in URLs for task management. The backend will implicitly filter tasks based on the `user_id` derived from the authenticated JWT. This approach is consistent with common REST API practices and fully satisfies the constitution's requirement to "Filter all queries by authenticated user's user_id."
-   **UI Requirements**: The UI components and page structures defined in the spec are consistent with the constitution's requirements.
-   **Required Deliverables**: The plan aims to fulfill all required deliverables as outlined in the constitution.

No significant violations are detected.

## Architecture Sketch

```mermaid
graph TD
    User --- Frontend
    Frontend -- REST/HTTPS, JWT --> Backend
    Backend -- SQL/AsyncPG --> Database

    subgraph "Frontend (Next.js v16.0.6)"
        Frontend[Web Browser (User Interface)]
        Frontend -- "Authentication (Better Auth)" --> Login/RegisterPage
        Frontend -- "Task Management (CRUD, Filter, Sort)" --> DashboardPage
        Frontend -- "API Client (frontend/lib/api.ts)" --> APIClient
    end

    subgraph "Backend (FastAPI v0.123.5)"
        Backend[FastAPI Application]
        Backend -- "Auth Router (/api/auth)" --> AuthEndpoints
        Backend -- "Tasks Router (/api/tasks)" --> TaskEndpoints
        Backend -- "Security (JWT Verification)" --> JWTMiddleware
        Backend -- "ORM (SQLModel)" --> DataAccessLayer
        AuthEndpoints -- "User Management" --> DataAccessLayer
        TaskEndpoints -- "Task Management" --> DataAccessLayer
        JWTMiddleware -- "Extract user_id" --> TaskEndpoints
    end

    subgraph "Database (Neon Serverless PostgreSQL)"
        Database[PostgreSQL Database]
        DataAccessLayer -- "Read/Write" --> UsersTable
        DataAccessLayer -- "Read/Write" --> TasksTable
        UsersTable[(users)]
        TasksTable[(tasks)]
    end

    Login/RegisterPage -- "Register/Login Request" --> AuthEndpoints
    DashboardPage -- "Task CRUD Requests" --> TaskEndpoints

    style Frontend fill:#f9f,stroke:#333,stroke-width:2px
    style Backend fill:#ccf,stroke:#333,stroke-width:2px
    style Database fill:#cfc,stroke:#333,stroke-width:2px
    style UsersTable fill:#fcf,stroke:#333,stroke-width:1px
    style TasksTable fill:#fcf,stroke:#333,stroke-width:1px
    style Login/RegisterPage fill:#eee,stroke:#333,stroke-width:1px
    style DashboardPage fill:#eee,stroke:#333,stroke-width:1px
    style AuthEndpoints fill:#fcf,stroke:#333,stroke-width:1px
    style TaskEndpoints fill:#fcf,stroke:#333,stroke-width:1px
    style JWTMiddleware fill:#ffe,stroke:#333,stroke-width:1px
    style DataAccessLayer fill:#ffe,stroke:#333,stroke-width:1px
    style APIClient fill:#ffe,stroke:#333,stroke-width:1px
```

**Description**:
The system follows a typical client-server architecture. The **Frontend**, built with Next.js, serves as the user interface and interacts with the Backend via RESTful API calls. User authentication is handled via a library like Better Auth, which issues JWTs upon successful login. These JWTs are then sent with subsequent requests to protected Backend endpoints in the `Authorization` header.

The **Backend**, implemented with FastAPI, handles API requests, authenticates users by verifying JWTs, and performs CRUD operations on tasks. SQLModel acts as the ORM to interact with the **PostgreSQL Database**. All API interactions involving tasks are implicitly scoped to the authenticated user via their `user_id` extracted from the JWT, ensuring data isolation.

**Data Flow (Tasks)**:
1.  **Client Request**: User performs an action (e.g., create task, view tasks) on the Frontend.
2.  **API Call**: Frontend's API client sends an authenticated HTTP request (with JWT) to a Backend endpoint (e.g., `POST /api/tasks`, `GET /api/tasks`).
3.  **Backend Processing**:
    *   `JWTMiddleware` intercepts the request, validates the JWT, and extracts the `user_id`.
    *   The relevant `TaskEndpoints` handler receives the request.
    *   `DataAccessLayer` (via SQLModel) interacts with the `tasks` table, always filtering or associating operations with the extracted `user_id`.
4.  **Database Interaction**: PostgreSQL stores or retrieves task data.
5.  **Backend Response**: Backend sends a JSON response to the Frontend.
6.  **Frontend Update**: Frontend updates the UI based on the response.

**Authentication Flow (JWT-based)**:
1.  **User attempts Login/Registration**: Frontend sends credentials to `POST /api/auth/login` or `POST /api/auth/register`.
2.  **Backend Credential Verification**: Backend verifies credentials (e.g., hashes password, checks against `users` table).
3.  **JWT Issuance**: If successful, Backend generates a JWT containing the `user_id` and returns it to the Frontend.
4.  **Frontend Storage**: Frontend securely stores the JWT (e.g., in `localStorage` or `httpOnly` cookies).
5.  **Authenticated Requests**: For protected routes, Frontend includes the JWT in the `Authorization: Bearer <token>` header of every request.
6.  **Backend JWT Verification**: Backend's `JWTMiddleware` intercepts, decodes, and validates the JWT. If valid, the `user_id` from the token is used to authorize and scope subsequent operations. If invalid/expired, a 401 Unauthorized response is sent.
7.  **Logout**: Frontend client-side invalidates the stored JWT, redirecting the user to the login page.

**Error Handling**:
-   **Frontend**: Displays specific error messages received from the Backend API (e.g., validation errors, unauthorized access). Redirects to login on 401.
-   **Backend**: Returns appropriate HTTP status codes (400 Bad Request, 401 Unauthorized, 404 Not Found, 409 Conflict) with descriptive JSON error messages. Proper logging of server-side errors.


| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| [e.g., 4th project] | [current need] | [why 3 projects insufficient] |
| [e.g., Repository pattern] | [specific problem] | [why direct DB access insufficient] |

## Section Structure & Organization

This plan is structured to provide a comprehensive overview of the Full-Stack Todo Web Application's implementation, broken down into logical sections to guide development.

1.  **Summary**: High-level overview of the feature and technical approach.
2.  **Technical Context**: Defines the core technologies, versions, and environmental settings.
3.  **Constitution Check**: Verifies alignment with project-wide architectural and development principles.
4.  **Architecture Sketch**: Visual and descriptive overview of system components and their interactions, including data and authentication flows.
5.  **Data Model**: Details the structure and relationships of key entities (User, Task), including validation rules and SQLModel representations.
6.  **API Contracts**: Formal definition of all backend REST endpoints using OpenAPI Specification.
7.  **Quickstart Guide**: Instructions for rapid setup and execution of the application.
8.  **Key Technical Decisions**: Documents critical design choices, their alternatives, and rationale.
9.  **Testing & Quality Validation**: Outlines the testing strategy for unit, integration, and E2E tests.
10. **Phased Development Plan**: Organizes the implementation into distinct phases, from research to deployment considerations.
11. **Future Enhancements**: Notes for potential future features and improvements.

## Key Technical Decisions

This section documents significant technical decisions, the alternatives considered, and the rationale behind the final choices.

### 1. Frontend Framework
-   **Options Considered**: React (standalone), Vue.js, Angular, Next.js.
-   **Trade-offs**:
    -   React (standalone): High flexibility, large ecosystem, but requires manual setup for routing, SSR, etc.
    -   Vue.js/Angular: Strong frameworks, but not specified in constitution and would introduce new learning curves.
    -   Next.js: React-based, full-stack capabilities (SSR, SSG, API routes), excellent developer experience, strong community support.
-   **Decision**: Next.js v16.0.6 (App Router).
-   **Rationale**: Mandated by the project constitution. Provides a robust, modern, and scalable foundation for the frontend, aligning with current industry best practices for web development. The App Router offers advanced features for routing and data fetching.

### 2. Backend Framework
-   **Options Considered**: Django, Flask, Express.js (Node.js), FastAPI.
-   **Trade-offs**:
    -   Django: Full-featured, ORM included, but can be opinionated and heavier for simpler APIs.
    -   Flask: Microframework, highly flexible, but requires more manual setup for complex APIs.
    -   Express.js: Popular for Node.js, but constitution mandates Python for backend.
    -   FastAPI: High performance, async support, built-in Pydantic for data validation/serialization, OpenAPI generation.
-   **Decision**: FastAPI v0.123.5.
-   **Rationale**: Mandated by the project constitution. Offers excellent performance, type hints for robust code, and automatic OpenAPI documentation, which integrates well with the spec-driven approach.

### 3. ORM / Database Interaction
-   **Options Considered**: SQLAlchemy (standalone), Peewee, PonyORM, SQLModel.
-   **Trade-offs**:
    -   SQLAlchemy: Powerful and flexible, but can be verbose for simple models.
    -   Peewee/PonyORM: Simpler ORMs, but less feature-rich than SQLAlchemy.
    -   SQLModel: Built on SQLAlchemy and Pydantic, combines benefits of both, offering type-hinted models and automatic validation.
-   **Decision**: SQLModel.
-   **Rationale**: Mandated by the project constitution. It leverages Pydantic for data validation and type hinting, providing a consistent and efficient way to define database models and interact with the database, especially when used with FastAPI.

### 4. Database System
-   **Options Considered**: MySQL, SQLite, MongoDB, PostgreSQL.
-   **Trade-offs**:
    -   MySQL: Popular, mature, good performance.
    -   SQLite: File-based, good for local development/small apps, not scalable for multi-user.
    -   MongoDB: NoSQL, flexible schema, but not ideal for relational data like tasks with clear relationships.
    -   PostgreSQL: Robust, highly extensible, excellent for relational data, strong support for JSON/indexing.
-   **Decision**: Neon Serverless PostgreSQL.
-   **Rationale**: Mandated by the project constitution. Provides a scalable, reliable, and managed PostgreSQL solution, suitable for cloud deployments and offers serverless capabilities.

### 5. Authentication Mechanism
-   **Options Considered**: Session-based, OAuth, API Keys, JWT.
-   **Trade-offs**:
    -   Session-based: Requires server-side state, less scalable for distributed systems.
    -   OAuth: Complex for simple user authentication, more suited for third-party access.
    -   API Keys: Simple, but less secure for user authentication.
    -   JWT: Stateless, scalable, widely supported, secure if implemented correctly.
-   **Decision**: JWT (JSON Web Tokens) issued by Better Auth (Frontend) and verified by Backend.
-   **Rationale**: Mandated by the project constitution. Offers a stateless and scalable authentication solution. The `python-jose` library will be used in the backend for secure token verification.

### 6. Backend API Path for User-Specific Resources
-   **Options Considered**:
    1.  Include `user_id` in path: `/api/users/{user_id}/tasks`
    2.  Infer `user_id` from JWT: `/api/tasks`
-   **Trade-offs**:
    -   Option 1: Explicitly shows user context, but can be redundant if `user_id` is already in JWT. Potential security risk if `user_id` in path doesn't match JWT.
    -   Option 2: Cleaner URLs, relies entirely on JWT for context, reduces surface area for `user_id` manipulation in requests.
-   **Decision**: Infer `user_id` from JWT for `/api/tasks` endpoints.
-   **Rationale**: Aligns with the constitution's requirement to "Filter all queries by authenticated user's user_id" while providing a cleaner, more secure API design where the user context is managed implicitly via authentication, not explicitly exposed in the URL path. This is a common and recommended practice for RESTful APIs.

### 7. Password Hashing Algorithm
-   **Options Considered**: MD5, SHA-1, SHA-256, bcrypt, scrypt, Argon2.
-   **Trade-offs**:
    -   MD5/SHA-1: Cryptographically weak, not suitable for passwords.
    -   SHA-256: Better than MD5/SHA-1, but still vulnerable to brute-force attacks without salting and stretching.
    -   bcrypt/scrypt/Argon2: Designed for password hashing, slow by design, resistant to brute-force and rainbow table attacks.
-   **Decision**: `bcrypt` via `passlib`.
-   **Rationale**: `bcrypt` is a strong, industry-standard password hashing algorithm that is resistant to brute-force attacks due to its adaptive nature (cost factor). It's well-supported by `passlib`, which is commonly used with FastAPI for secure password handling.

---

## Testing & Quality Validation

A multi-layered testing strategy will be employed to ensure the quality, reliability, and correctness of the Full-Stack Todo Web Application.

### 1. Unit Tests
-   **Scope**: Individual functions, methods, and small logical units.
-   **Frameworks**:
    -   **Backend**: `pytest`.
    -   **Frontend**: `Jest` and `React Testing Library`.
-   **Validation Checks**:
    -   **Backend**: Model validation, service logic, utility functions (e.g., JWT encoding/decoding), database interactions (mocked).
    -   **Frontend**: Individual React components rendering correctly, utility functions, reducer logic (if using state management like Redux/Zustand).

### 2. Integration Tests
-   **Scope**: Interactions between different components or services.
-   **Frameworks**:
    -   **Backend**: `pytest` with `httpx` (or FastAPI's `TestClient`) for API endpoint testing. Actual database interactions will be performed (using a test database).
    -   **Frontend**: `React Testing Library` for testing interactions between components or integration with API client (mocked API calls).
-   **Validation Checks**:
    -   **Backend**: API endpoint behavior (e.g., `POST /auth/register` creates user in DB, `GET /tasks` returns correct data for authenticated user), JWT token generation and verification, database schema and ORM operations, filtering and sorting logic.
    -   **Frontend**: Data fetching and rendering from mocked API, form submissions and state updates, navigation flows.

### 3. End-to-End (E2E) Tests
-   **Scope**: Entire application flow, simulating real user interactions through the UI to the backend and database.
-   **Framework**: `Playwright`.
-   **Validation Checks**:
    -   **User Authentication Lifecycle**: Registration, login, logout, session persistence, unauthorized access redirection.
    -   **Task Lifecycle**: Creating a task, viewing it, updating its title/description/status, deleting a task.
    -   **Filtering and Sorting**: Verify that tasks are correctly filtered by status and sorted by title/date.
    -   **Data Isolation**: Ensure a user can only see and modify their own tasks.
    -   **Error Handling**: Verify that error messages are displayed correctly in the UI for various backend errors (e.g., validation failures, unauthorized).

## Phased Development Plan

The implementation will follow a phased approach, building upon completed milestones.

### Phase 0: Research (Completed)
-   **Objective**: Identify and select suitable technologies, libraries, and frameworks based on project requirements and constitution. Resolve all "NEEDS CLARIFICATION" points.
-   **Deliverables**: `research.md`.

### Phase 1: Foundation (Completed)
-   **Objective**: Define the core architectural components, data models, and API contracts. Set up initial project structure.
-   **Deliverables**: `data-model.md`, `contracts/openapi.yaml`, `quickstart.md`, updated agent context.

### Phase 2: Core Backend Implementation
-   **Objective**: Develop the FastAPI backend, including user authentication (registration, login), JWT handling, and core Task CRUD operations.
-   **Key Tasks**:
    -   Database setup and connection with SQLModel.
    -   User model and endpoints (register, login).
    -   JWT generation and verification middleware.
    -   Task model and CRUD endpoints.
    -   Implement `user_id` filtering for all task operations.
    -   Backend unit and integration tests.

### Phase 3: Core Frontend Implementation
-   **Objective**: Develop the Next.js frontend, including user interface for authentication and basic Task CRUD operations.
-   **Key Tasks**:
    -   Next.js project setup, Tailwind CSS integration.
    -   Login and registration pages/components with Better Auth.
    -   Dashboard page to display tasks.
    -   API client integration for backend communication.
    -   Task listing and creation UI.
    -   Frontend unit and integration tests.

### Phase 4: Advanced Features & Refinements
-   **Objective**: Implement task filtering, sorting, task update/delete functionality in the UI, and comprehensive error handling.
-   **Key Tasks**:
    -   Task filtering and sorting UI components.
    -   Task editing and deletion UI.
    -   Robust error handling and user feedback across frontend and backend.
    -   E2E tests with Playwright.

### Phase 5: Deployment & Documentation
-   **Objective**: Prepare the application for deployment and finalize documentation.
-   **Key Tasks**:
    -   Containerization (Docker Compose for local development).
    -   Deployment scripts/configurations (e.g., Vercel for frontend, Render/Fly.io for backend).
    -   Update `README.md` with complete setup and usage instructions.
    -   Final review of all specs and documentation.

## Future Enhancements

These are potential features for future development, beyond the scope of the current plan.

-   **Advanced Task States**: Implement more granular task states (e.g., 'blocked', 'on hold').
-   **Task Priorities**: Add priority levels (e.g., High, Medium, Low) to tasks.
-   **Due Dates**: Allow users to set due dates for tasks and implement reminders.
-   **Sharing/Collaboration**: Enable users to share tasks or collaborate on task lists.
-   **User Roles**: Introduce admin/standard user roles with different permissions.
-   **Frontend State Management**: Integrate a more sophisticated state management library (e.g., Zustand, Jotai) if global state complexity increases significantly.
-   **Analytics/Monitoring**: Implement logging, metrics, and tracing for production environments.
-   **Email Notifications**: Send email notifications for task reminders or status changes.
