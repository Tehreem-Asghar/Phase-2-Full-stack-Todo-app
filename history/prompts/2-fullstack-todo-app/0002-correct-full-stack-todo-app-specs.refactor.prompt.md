---
id: 0002
title: Correct Full-Stack Todo App Specs
stage: refactor
date: 2025-12-04
surface: agent
model: gemini
feature: 2-fullstack-todo-app
branch: 002-fullstack-todo-app
user: user
command: /sp.specify
labels: ["spec", "refactor"]
links:
  spec: specs/2-fullstack-todo-app/spec.md
  ticket: null
  adr: null
  pr: null
files:
  - specs/2-fullstack-todo-app/spec.md
  - specs/2-fullstack-todo-app/checklists/requirements.md
tests:
  []
---

## Prompt

✦ Review & Correct Feature Specification Task: Review the existing Phase II Full-Stack Todo Web Application specification and fix potential issues. Points to Check & Correct: 1. **User ID Type Consistency** - Ensure `tasks.user_id` column type matches Better Auth user ID type (string vs integer). 2. **JWT Authentication Enforcement** - Verify that all task and auth API endpoints enforce JWT validation. - Add missing 401 Unauthorized responses if absent. 3. **API Request/Response Details** - Confirm request bodies match backend model (SQLModel + FastAPI). - Ensure all responses include `created_at` and `updated_at` fields. 4. **Database Indexes & Constraints** - Add missing indexes on `tasks.completed` if filtering will be used. - Ensure foreign key constraint between `tasks.user_id` → `users.id` exists. 5. **UI Navigation & Redirects** - Check login-protected routes redirect to `/login`. - Confirm logout clears JWT properly on frontend. 6. **Validation Rules** - Recheck password complexity and email format validation. - Ensure username, title, and description length limits are consistent across frontend, backend, and DB schema. 7. **Consistency Across Specs** - Ensure `/specs/features`, `/specs/api`, `/specs/database`, and `/specs/ui` are aligned. - Correct any mismatches in field names or endpoint paths. Instructions: - Correct these issues directly in the specification files. - Keep feature branch `002-fullstack-todo-app` and GEMINI.md updated. - Do not alter other unrelated sections.

## Response snapshot

Successfully reviewed and corrected the feature specification for the 'Full-Stack Todo Web Application'.

## Outcome

- ✅ Impact: Corrected and improved the existing specification.
- 🧪 Tests: No tests were run.
- 📁 Files: 2 files updated.
- 🔁 Next prompts: /sp.plan
- 🧠 Reflection: The process involved updating an existing spec and its checklist, and creating a new PHR to document the changes.

## Evaluation notes (flywheel)

- Failure modes observed: None.
- Graders run and results (PASS/FAIL): PASS
- Prompt variant (if applicable): null
- Next experiment (smallest change to try): n/a
