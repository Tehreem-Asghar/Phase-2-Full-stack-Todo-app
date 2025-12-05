---
id: 0001
title: Create Full-Stack Todo App Specs
stage: spec
date: 2025-12-04
surface: agent
model: gemini
feature: 2-fullstack-todo-app
branch: 002-fullstack-todo-app
user: user
command: /sp.specify
labels: ["spec", "full-stack"]
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

create detailed specifications for Phase II: Full-Stack Todo Web Application. These specs will be used to guide all development across frontend, backend, authentication, API, and database layers. Follow these rules strictly: 1. **Project Reference** - Project Name: hackathon-todo - Current Phase: Phase II (Full-Stack Web App) - Tech Stack: Frontend Next.js 16+ + TypeScript + Tailwind, Backend FastAPI + SQLModel, Database Neon PostgreSQL, Auth Better Auth with JWT - Monorepo structure as defined in GEMINI.md 2. **Feature Specifications** - For each feature (Task CRUD, Authentication, Filtering/Sorting): - Define **User Stories** - Define **Acceptance Criteria** - Define **Validation Rules** (e.g., title length, JWT validation) - Store all feature specs under `/specs/features/` 3. **API Specifications** - For all endpoints (GET, POST, PUT, DELETE, PATCH): - Define Request Parameters - Define Request Body - Define Response Body - Define HTTP Status Codes - Include authentication requirements - Store all API specs under `/specs/api/` 4. **Database Specifications** - Define all tables, fields, types, relationships, indexes - Include foreign key constraints for user-task relationships - Include created_at / updated_at fields - Store database schema in `/specs/database/schema.md` 5. **UI Specifications** - Define all frontend components and pages - Include layout, responsive design, interactivity - Include integration with API endpoints and JWT-based auth - Store UI specs in `/specs/ui/` 6. **Spec Linking** - Cross-reference features with API, database, and UI specs using: `@specs/features/feature-name.md` `@specs/api/rest-endpoints.md` `@specs/database/schema.md` `@specs/ui/components.md` 7. **Output Format** - Generate **Markdown files** for each spec - Include headings, tables, bullet points for clarity - Each spec should be self-contained, but cross-reference other specs where needed 8. **Rules** - Do not implement code yet - Only generate detailed specifications - Follow the Phase II GEMINI.md constitution - Always ask for clarification if a spec seems ambiguous --- **Goal:** At the end of this step, the `/specs/` folder should contain complete, structured, detailed specifications ready for code implementation for all Phase II features.

## Response snapshot

Successfully created the feature specification, validation checklist, and associated files for the 'Full-Stack Todo Web Application'.

## Outcome

- ✅ Impact: Created a comprehensive specification for the new feature.
- 🧪 Tests: No tests were run.
- 📁 Files: 2 files created.
- 🔁 Next prompts: /sp.plan
- 🧠 Reflection: The process involved multiple steps, including workarounds for script failures.

## Evaluation notes (flywheel)

- Failure modes observed: The `create-new-feature.ps1` script failed due to long arguments. The `create-phr.sh` script failed because `bash` was not available.
- Graders run and results (PASS/FAIL): PASS
- Prompt variant (if applicable): null
- Next experiment (smallest change to try): n/a
