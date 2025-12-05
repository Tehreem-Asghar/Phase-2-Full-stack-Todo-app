# Tasks: Full-Stack Todo Web Application

**Input**: Design documents from `/specs/002-fullstack-todo-app/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: The examples below include test tasks. Tests are OPTIONAL - only include them if explicitly requested in the feature specification.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Web app**: `backend/src/`, `frontend/src/`
- Paths shown below assume this web app structure.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure for the monorepo, including `docker-compose.yml` for the database.

- [ ] T001 Create project root `README.md` and update with quickstart instructions in `README.md`
- [ ] T002 Initialize git repository and `.gitignore` in project root
- [ ] T003 Create `docker-compose.yml` for PostgreSQL database service in project root
- [ ] T004 Create a `.env.example` file in the project root with placeholders for `DATABASE_URL`, `SECRET_KEY`, `ALGORITHM`
- [ ] T005 [P] Create `backend/` directory and initialize Python project
- [ ] T006 [P] Create `frontend/` directory and initialize Next.js project with TypeScript and Tailwind CSS

---
## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [ ] T007 Configure `backend/` project structure and initial `main.py`
- [ ] T008 [P] Install backend dependencies: `fastapi`, `uvicorn`, `sqlmodel`, `python-jose[cryptography]`, `passlib[bcrypt]`, `psycopg` in `backend/requirements.txt`
- [ ] T009 [P] Configure `frontend/` project structure for Next.js 16 (App Router), TypeScript, and Tailwind CSS
- [ ] T010 [P] Install frontend dependencies: `react`, `react-dom`, `next`, `tailwindcss`, `autoprefixer`, `postcss`, `better-auth` (placeholder) in `frontend/package.json`
- [ ] T011 Implement database connection and session management for SQLModel in `backend/database.py`
- [ ] T012 Create `User` SQLModel in `backend/models/user.py` based on `data-model.md`
- [ ] T013 Create `Task` SQLModel in `backend/models/task.py` based on `data-model.md`
- [ ] T014 Implement password hashing utility functions using `passlib` in `backend/security.py`
- [ ] T015 Implement JWT token creation and verification utilities using `python-jose` in `backend/security.py`
- [ ] T016 Implement FastAPI dependency for authenticated user extraction from JWT in `backend/dependencies.py`
- [ ] T017 Configure CORS middleware in `backend/main.py`

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---
## Phase 3: User Story 1 - User Registration (Priority: P1) 🎯 MVP

**Goal**: Enable new users to create an account with username, email, and password.

**Independent Test**: Successfully register a new user via the API and verify account creation in the database.

- [ ] T018 [P] [US1] Create unit tests for user registration backend logic in `backend/tests/test_auth_register.py`
- [ ] T019 [US1] Implement user registration endpoint (`POST /auth/register`) in `backend/routers/auth.py`
- [ ] T020 [US1] Add backend input validation for registration (username, email, password) in `backend/routers/auth.py`
- [ ] T021 [US1] Generate JWT on successful registration and return to client in `backend/routers/auth.py`
- [ ] T022 [P] [US1] Create frontend registration page (`/register`) with form in `frontend/app/register/page.tsx`
- [ ] T023 [US1] Implement frontend registration form validation and submission to backend API in `frontend/app/register/page.tsx`
- [ ] T024 [US1] Handle successful registration (store JWT, redirect to dashboard) in `frontend/app/register/page.tsx`
- [ ] T025 [US1] Display API error messages to user on registration page in `frontend/app/register/page.tsx`

---
## Phase 4: User Story 2 - User Login (Priority: P1)

**Goal**: Enable existing users to log in with their credentials and remember their session.

**Independent Test**: Successfully log in an existing user via the API, receive and store JWT, and access a protected route.

- [ ] T026 [P] [US2] Create unit tests for user login backend logic in `backend/tests/test_auth_login.py`
- [ ] T027 [US2] Implement user login endpoint (`POST /auth/login`) in `backend/routers/auth.py`
- [ ] T028 [US2] Verify user credentials and generate JWT on successful login in `backend/routers/auth.py`
- [ ] T029 [P] [US2] Create frontend login page (`/login`) with form in `frontend/app/login/page.tsx`
- [ ] T030 [US2] Implement frontend login form validation and submission to backend API in `frontend/app/login/page.tsx`
- [ ] T031 [US2] Handle successful login (store JWT, redirect to dashboard) in `frontend/app/login/page.tsx`
- [ ] T032 [US2] Display API error messages to user on login page in `frontend/app/login/page.tsx`
- [ ] T033 [US2] Implement client-side JWT storage and retrieval for persistent session (e.g., `localStorage`) in `frontend/lib/auth.ts`
- [ ] T034 [US2] Implement frontend mechanism to automatically log in using stored JWT on app load in `frontend/lib/auth.ts`
- [ ] T035 [US2] Implement frontend protected route redirection to `/login` if unauthenticated/expired JWT in `frontend/middleware.ts`

---
## Phase 5: User Story 3 - User Logout (Priority: P1)

**Goal**: Enable logged-in users to securely log out of their account.

**Independent Test**: Successfully log out a user from the frontend, clear JWT, and redirect to login page.

- [ ] T036 [US3] Implement frontend logout functionality (clear JWT, redirect to `/login`) in `frontend/components/Navbar.tsx`
- [ ] T037 [US3] Ensure client-side JWT invalidation on logout in `frontend/lib/auth.ts`

---
## Phase 6: User Story 5 - Create Task (Priority: P2)

**Goal**: Allow logged-in users to create new tasks with a title and optional description.

**Independent Test**: Successfully create a new task via the API and verify its persistence in the database and association with the correct user.

- [ ] T038 [P] [US5] Create unit tests for task creation backend logic in `backend/tests/test_tasks_create.py`
- [ ] T039 [US5] Implement task creation endpoint (`POST /api/tasks`) in `backend/routers/tasks.py`
- [ ] T040 [US5] Ensure `user_id` from JWT is associated with the new task in `backend/routers/tasks.py`
- [ ] T041 [US5] Add backend input validation for task creation (title) in `backend/routers/tasks.py`
- [ ] T042 [P] [US5] Create frontend component for creating new tasks (e.g., a form) in `frontend/components/TaskForm.tsx`
- [ ] T043 [US5] Implement frontend task creation form submission to backend API in `frontend/components/TaskForm.tsx`
- [ ] T044 [US5] Display API error messages for task creation in `frontend/components/TaskForm.tsx`

---
## Phase 7: User Story 6 - View Tasks (Priority: P2)

**Goal**: Allow logged-in users to view a list of all their tasks.

**Independent Test**: Successfully retrieve a list of tasks for the authenticated user via the API and display them on the dashboard.

- [ ] T045 [P] [US6] Create unit tests for task viewing backend logic in `backend/tests/test_tasks_view.py`
- [ ] T046 [US6] Implement task listing endpoint (`GET /api/tasks`) in `backend/routers/tasks.py`
- [ ] T047 [US6] Ensure task listing returns only tasks belonging to the authenticated `user_id` in `backend/routers/tasks.py`
- [ ] T048 [P] [US6] Create frontend `TaskList` component to render tasks in `frontend/components/TaskList.tsx`
- [ ] T049 [P] [US6] Create frontend `TaskItem` component to display a single task in `frontend/components/TaskItem.tsx`
- [ ] T050 [US6] Integrate `TaskList` into the dashboard page (`/`) and fetch tasks from the backend API in `frontend/app/page.tsx`
- [ ] T051 [US6] Handle and display empty state for task list in `frontend/app/page.tsx`

---
## Phase 8: User Story 7 - Update Task Status (Priority: P2)

**Goal**: Allow logged-in users to update the status of a task (e.g., 'todo', 'in-progress', 'completed').

**Independent Test**: Successfully update a task's status via the API and verify the change in the database and UI.

- [ ] T052 [P] [US7] Create unit tests for task status update backend logic in `backend/tests/test_tasks_update_status.py`
- [ ] T053 [US7] Implement task update endpoint (`PUT /api/tasks/{task_id}`) to handle status changes in `backend/routers/tasks.py`
- [ ] T054 [US7] Ensure `updated_at` timestamp is automatically updated on task status change in `backend/routers/tasks.py`
- [ ] T055 [US7] Add backend validation for task status (enum values) and ownership in `backend/routers/tasks.py`
- [ ] T056 [P] [US7] Add UI control (e.g., dropdown, checkbox) to `TaskItem` component for status update in `frontend/components/TaskItem.tsx`
- [ ] T057 [US7] Implement frontend logic to send status update requests to backend API in `frontend/components/TaskItem.tsx`

---
## Phase 9: User Story 8 - Edit Task (Title & Description) (Priority: P2)

**Goal**: Allow logged-in users to edit the title and description of an existing task.

**Independent Test**: Successfully update a task's title and description via the API and verify the change in the database and UI.

- [ ] T058 [P] [US8] Create unit tests for task edit backend logic in `backend/tests/test_tasks_edit.py`
- [ ] T059 [US8] Extend task update endpoint (`PUT /api/tasks/{task_id}`) to handle title and description changes in `backend/routers/tasks.py`
- [ ] T060 [US8] Add backend validation for task title and ownership in `backend/routers/tasks.py`
- [ ] T061 [P] [US8] Add UI controls (e.g., input fields) to `TaskItem` component for editing title/description in `frontend/components/TaskItem.tsx`
- [ ] T062 [US8] Implement frontend logic to send title/description update requests to backend API in `frontend/components/TaskItem.tsx`

---
## Phase 10: User Story 9 - Delete Task (Priority: P2)

**Goal**: Allow logged-in users to delete a task they no longer need.

**Independent Test**: Successfully delete a task via the API and verify its removal from the database and UI.

- [ ] T063 [P] [US9] Create unit tests for task deletion backend logic in `backend/tests/test_tasks_delete.py`
- [ ] T064 [US9] Implement task deletion endpoint (`DELETE /api/tasks/{task_id}`) in `backend/routers/tasks.py`
- [ ] T065 [US9] Add backend validation for task ownership before deletion in `backend/routers/tasks.py`
- [ ] T066 [P] [US9] Add UI control (e.g., button) to `TaskItem` component for task deletion in `frontend/components/TaskItem.tsx`
- [ ] T067 [US9] Implement frontend logic to send delete request to backend API in `frontend/components/TaskItem.tsx`
- [ ] T068 [US9] Implement frontend confirmation dialog for task deletion in `frontend/components/TaskItem.tsx`

---
## Phase 11: User Story 10 - Filter Tasks (Priority: P3)

**Goal**: Allow logged-in users to filter their tasks by status ('All', 'Todo', 'In-Progress', 'Completed').

**Independent Test**: Successfully filter tasks by status via the API and verify the correct subset of tasks is displayed in the UI.

- [ ] T069 [P] [US10] Create unit tests for task filtering backend logic in `backend/tests/test_tasks_filter.py`
- [ ] T070 [US10] Implement task filtering logic for `GET /api/tasks?filter=...` endpoint in `backend/routers/tasks.py`
- [ ] T071 [P] [US10] Create frontend `TaskFilter` component (e.g., radio buttons, dropdown) in `frontend/components/TaskFilter.tsx`
- [ ] T072 [US10] Integrate `TaskFilter` component into dashboard and apply filter parameters to API calls in `frontend/app/page.tsx`
- [ ] T073 [US10] Update task list display based on filter selection in `frontend/app/page.tsx`

---
## Phase 12: User Story 11 - Sort Tasks (Priority: P3)

**Goal**: Allow logged-in users to sort their tasks by creation date or title.

**Independent Test**: Successfully sort tasks by creation date and title via the API and verify the order of tasks in the UI.

- [ ] T074 [P] [US11] Create unit tests for task sorting backend logic in `backend/tests/test_tasks_sort.py`
- [ ] T075 [US11] Implement task sorting logic for `GET /api/tasks?sort=...` endpoint in `backend/routers/tasks.py`
- [ ] T076 [P] [US11] Extend frontend `TaskFilter` component with sorting controls (e.g., dropdown) in `frontend/components/TaskFilter.tsx`
- [ ] T077 [US11] Integrate sorting controls into dashboard and apply sort parameters to API calls in `frontend/app/page.tsx`
- [ ] T078 [US11] Update task list display based on sort selection in `frontend/app/page.tsx`

---
## Phase 13: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories, deployment, and final documentation.

- [ ] T079 [P] Implement comprehensive backend error handling and logging (e.g., Sentry integration) in `backend/main.py`
- [ ] T080 [P] Implement comprehensive frontend error handling and logging (e.g., Sentry integration) in `frontend/lib/error-logger.ts`
- [ ] T081 Review and refine all API response messages for consistency and clarity in `backend/models/*.py`, `backend/routers/*.py`
- [ ] T082 Implement Dockerfile for backend in `backend/Dockerfile`
- [ ] T083 Implement Dockerfile for frontend in `frontend/Dockerfile`
- [ ] T084 Finalize `docker-compose.yml` to include backend and frontend services in project root
- [ ] T085 Finalize `README.md` with complete setup, usage, and deployment instructions
- [ ] T086 [P] Conduct full E2E testing using Playwright scripts in `e2e-tests/`
- [ ] T087 Accessibility audit and improvements across the frontend UI
- [ ] T088 Performance optimization review for both frontend and backend

---
## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3-12)**: All depend on Foundational phase completion
  - User stories can then proceed in parallel (if staffed) or sequentially in priority order.
- **Polish (Phase 13)**: Depends on all user stories being complete.

### User Story Dependencies

- **User Stories 1, 2, 3 (Authentication)**: Can start after Foundational phase. US2 depends on US1. US3 depends on US2.
- **User Stories 5, 6, 7, 8, 9 (Task CRUD)**: All depend on successful authentication (US1, US2, US3).
  - US5 (Create Task) and US6 (View Tasks) can be implemented in parallel.
  - US7 (Update Task Status), US8 (Edit Task), US9 (Delete Task) depend on US6 (View Tasks).
- **User Stories 10, 11 (Filtering & Sorting)**: Both depend on Task CRUD being functional (US5, US6).

### Within Each User Story

- Tests (if included) MUST be written and FAIL before implementation.
- Models before services.
- Services before endpoints.
- Core implementation before integration.
- Story complete before moving to next priority.

### Parallel Opportunities

- All Setup tasks marked [P] can run in parallel.
- All Foundational tasks marked [P] can run in parallel (within Phase 2).
- Once Foundational phase completes, user stories can start in parallel based on dependencies.
- All tests for a user story marked [P] can run in parallel.
- Tasks within a story marked [P] can run in parallel if they operate on different files/components.

---
## Parallel Example: User Story 1 (Registration)

```bash
# Developer 1: Backend Implementation
Task: "Create unit tests for user registration backend logic in `backend/tests/test_auth_register.py`"
Task: "Implement user registration endpoint (`POST /auth/register`) in `backend/routers/auth.py`"
Task: "Add backend input validation for registration (username, email, password) in `backend/routers/auth.py`"
Task: "Generate JWT on successful registration and return to client in `backend/routers/auth.py`"

# Developer 2: Frontend Implementation
Task: "Create frontend registration page (`/register`) with form in `frontend/app/register/page.tsx`"
Task: "Implement frontend registration form validation and submission to backend API in `frontend/app/register/page.tsx`"
Task: "Handle successful registration (store JWT, redirect to dashboard) in `frontend/app/register/page.tsx`"
Task: "Display API error messages to user on registration page in `frontend/app/register/page.tsx`"
```

---
## Implementation Strategy

### MVP First (User Story 1 & 2 - Core Auth)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL - blocks all stories)
3. Complete Phase 3: User Story 1 (Registration)
4. Complete Phase 4: User Story 2 (Login)
5. **STOP and VALIDATE**: Test User Stories 1 and 2 independently.
6. Deploy/demo if ready (minimal functional application).

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test independently → Deploy/Demo
3. Add User Story 2 → Test independently → Deploy/Demo
4. Continue with subsequent user stories in priority order (US3, US5, US6...).
5. Each story adds value without breaking previous stories.

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together.
2. Once Foundational is done:
   - Developer A: User Story 1, 3 (Auth)
   - Developer B: User Story 2, 5 (Auth & Create Task)
   - Developer C: User Story 6, 7 (View & Update Task)
3. Stories complete and integrate independently.

---
## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Verify tests fail before implementing
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Avoid: vague tasks, same file conflicts, cross-story dependencies that break independence
