# Feature Specification: Full-Stack Todo Web Application

**Feature Branch**: `002-fullstack-todo-app`
**Created**: 2025-12-04
**Status**: Draft
**Input**: User description: "create detailed specifications for Phase II: Full-Stack Todo Web Application..."

## 1. Features

### 1.1. User Authentication

#### User Stories
- As a new user, I want to create an account so I can manage my tasks.
- As an existing user, I want to log in to access my tasks.
- As a logged-in user, I want to log out to secure my account.
- As a user, I want my session to be remembered so I don't have to log in every time.

#### Acceptance Criteria
- Account creation requires a unique username, a valid email, and a password.
- Passwords must be securely hashed and stored.
- Login requires a correct username/password combination.
- Successful login generates a JWT token for session management.
- The application protects routes that require authentication.
- Unauthorized users attempting to access protected routes are redirected to the `/login` page.
- If an API call is made with an expired JWT, the user should be logged out and redirected to the `/login` page.
- Logout should invalidate the JWT token on the client-side.

#### Validation Rules
- The following validation rules must be enforced on both the frontend and backend.
- **Username**: 3-20 characters, alphanumeric. `VARCHAR(20)` in database.
- **Email**: Must be a valid email format.
- **Password**: At least 8 characters, containing at least one uppercase letter, one lowercase letter, one number, and one special character.
- **Task Title**: 1-255 characters. `VARCHAR(255)` in database.
- **JWT token**: Must be validated on every request to a protected endpoint.

### 1.2. Task CRUD Operations

#### User Stories
- As a logged-in user, I want to create a new task so I can track what I need to do.
- As a logged-in user, I want to view a list of all my tasks.
- As a logged-in user, I want to update the status of a task (e.g., to "in-progress" or "completed").
- As a logged-in user, I want to edit the title and description of a task.
- As a logged-in user, I want to delete a task I no longer need.

#### Acceptance Criteria
- A new task must have a title.
- A task can optionally have a description.
- By default, a new task has a 'todo' status.
- Users can only view and manage their own tasks.
- Deleting a task is a permanent action.

### 1.3. Task Filtering and Sorting

#### User Stories
- As a logged-in user, I want to filter my tasks to see tasks by their status (e.g., 'todo', 'in-progress', 'completed').
- As a logged-in user, I want to sort my tasks by creation date or by title.

#### Acceptance Criteria
- Users can filter tasks by 'All', 'Todo', 'In-Progress', and 'Completed' statuses.
- Users can sort tasks by "Title (A-Z)" and "Date created (Newest first)".

## Non-Functional Requirements

### Security & Privacy
- The system must comply with GDPR/CCPA regulations for user data.
- User data must be retained for a maximum of 1 year after account deletion.
- Task data must be retained for a maximum of 1 year after task deletion.

### Performance & Scalability
- The system is expected to support a medium scale, with up to 1,000 users and 200 tasks per user.

## 2. API Specifications (@specs/api/rest-endpoints.md)

### 2.1. Auth Endpoints

- **POST /api/auth/register**
    - **Request Body**: `{ "username": "string", "email": "string", "password": "string" }`
    - **Response Body**: `{ "access_token": "string", "token_type": "bearer" }`
    - **Status Codes**: 201 Created, 400 Bad Request, 409 Conflict

- **POST /api/auth/login**
    - **Request Body**: `{ "username": "string", "password": "string" }`
    - **Response Body**: `{ "access_token": "string", "token_type": "bearer" }`
    - **Status Codes**: 200 OK, 401 Unauthorized

### 2.2. Task Endpoints

*Authentication: Requires JWT Bearer token in Authorization header. JWT payload contains basic user identification (user ID only).*

- **GET /api/tasks**
    - **Request Parameters**: `?filter=all|todo|in-progress|completed&sort=title|date`
    - **Response Body**: `[{ "id": "string", "title": "string", "description": "string", "status": "string", "created_at": "datetime", "updated_at": "datetime" }]`
    - **Status Codes**: 200 OK, 401 Unauthorized

- **POST /api/tasks**
    - **Request Body**: `{ "title": "string", "description": "string" }`
    - **Response Body**: `{ "id": "string", "title": "string", "description": "string", "status": "string", "created_at": "datetime", "updated_at": "datetime" }`
    - **Status Codes**: 201 Created, 400 Bad Request, 401 Unauthorized

- **PUT /api/tasks/{task_id}**
    - **Description**: Updates a task. The backend must ensure the `updated_at` timestamp is automatically updated upon any change to the task.
    - **Request Body**: `{ "title": "string", "description": "string", "status": "string" }`
    - **Response Body**: `{ "id": "string", "title": "string", "description": "string", "status": "string", "created_at": "datetime", "updated_at": "datetime" }`
    - **Status Codes**: 200 OK, 401 Unauthorized, 404 Not Found

- **DELETE /api/tasks/{task_id}**
    - **Response Body**: `{ "message": "Task deleted successfully" }`
    - **Status Codes**: 200 OK, 401 Unauthorized, 404 Not Found

## 3. Database Specifications (@specs/database/schema.md)

### `users` table
- `id` (VARCHAR(36), PRIMARY KEY)
- `username` (VARCHAR(20), UNIQUE, NOT NULL)
- `email` (VARCHAR(255), UNIQUE, NOT NULL)
- `hashed_password` (VARCHAR(255), NOT NULL)
- `created_at` (TIMESTAMP, NOT NULL, DEFAULT CURRENT_TIMESTAMP)
- `updated_at` (TIMESTAMP, NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)

### `tasks` table
- `id` (VARCHAR(36), PRIMARY KEY)
- `user_id` (VARCHAR(36), FOREIGN KEY to `users.id`)
- `title` (VARCHAR(255), NOT NULL)
- `description` (TEXT)
- `status` (VARCHAR(20), NOT NULL, DEFAULT 'todo')
- `created_at` (TIMESTAMP, NOT NULL, DEFAULT CURRENT_TIMESTAMP)
- `updated_at` (TIMESTAMP, NOT NULL, DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)
- **Indexes**: `user_id`, `status`

## 4. UI Specifications (@specs/ui/components.md, @specs/ui/pages.md)

### Pages
- **/ (Home Page)**: Displays the main todo list view. Redirects to `/login` if the user is not authenticated or their session (JWT) has expired.
- **/login**: Login page with a form for username and password.
- **/register**: Registration page with a form for username, email, and password.

### Components
- **Navbar**: Contains the app title, and login/register or logout buttons. On logout, the JWT should be cleared from client-side storage.
- **TaskItem**: Displays a single task, allowing updates to its title, description, and status.
- **TaskList**: Renders a list of TaskItem components.
- **TaskFilter**: Provides controls to filter and sort the task list by status and other criteria.
- **LoginForm**: A form for user login. It must enforce the defined validation rules. API errors should be displayed as specific messages to the user.
- **RegisterForm**: A form for user registration. It must enforce the defined validation rules. API errors should be displayed as specific messages to the user.

## Clarifications

### Session 2025-12-04
- Q: What are the specific data privacy and retention requirements for user and task data beyond basic security? → A: Comply with GDPR/CCPA for user data, retain task data for 1 year
- Q: Are there other task states besides "completed" (e.g., "pending", "in-progress"), or is it a simple binary? → A: Add "in-progress" state
- Q: How should API errors (e.g., 400 Bad Request, 409 Conflict) be communicated to the user in the UI? → A: Display specific error messages from API
- Q: What is the expected maximum number of users and tasks per user the system should support? → A: Medium scale: 1,000 users, 200 tasks/user
- Q: Are there specific JWT claims (e.g., roles, permissions) required for future features, or is basic user identification sufficient for now? → A: Basic user identification (user ID only) is sufficient
