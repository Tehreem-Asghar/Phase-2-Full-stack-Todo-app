---
id: 0003
title: Update project constitution for Phase II
stage: constitution
date_iso: 2025-12-04
surface: agent
model: gemini-1.5-flash
feature: none
branch: (current branch)
user: (current user)
command: /sp.constitution
labels: ["constitution", "update", "monorepo"]
links:
  spec: null
  ticket: null
  adr: null
  pr: null
files_yaml:
  - .specify/memory/constitution.md
  - .specify/templates/plan-template.md
  - .specify/templates/tasks-template.md
  - README.md
tests_yaml: []
prompt_text: |-
  /sp.constitution  # Spec-Kit Constitution for Phase II: Full-Stack Todo Web Application

  ## Purpose
  This constitution defines the rules, workflows, and structure for building the Phase II
  Todo Web Application using Spec-Kit and AI-driven development tools (Gemini CLI).
  The system must follow spec-driven development across frontend (Next.js),
  backend (FastAPI), authentication, and database layers.

  ## Project Evolution
  The project has evolved from:
  - Phase I: Python Console Todo App (in-memory)
  to
  - Phase II: Full-Stack Multi-User Web Application (Next.js + FastAPI + PostgreSQL)

  All implementation must follow the Phase II specifications.

  ## Monorepo Structure (Required)
  The repository must follow this exact structure:

  hackathon-todo/
    ├── .spec-kit/
    │     └── config.yaml
    ├── specs/
    │     ├── overview.md
    │     ├── architecture.md
    │     ├── features/
  │     │     ├── task-crud.md
  │     │     ├── authentication.md
  │     ├── api/
  │     │     └── rest-endpoints.md
  │     ├── database/
  │     │     └── schema.md
  │     └── ui/
  │           ├── components.md
  │           └── pages.md
  ├── frontend/
  │     ├── GEMINI.md
  │     └── Next.js app
  ├── backend/
  │     ├── GEMINI.md
  │     └── FastAPI app
  ├── docker-compose.yml
  ├── GEMINI.md
  └── README.md

  ## Development Principles
  1. **Spec-First Development**
     Every feature must be derived from a spec inside /specs.
     No implementation should start without referencing the spec.

  2. **Layered GEMINI.md Files**
     - Root GEMINI.md → project rules
     - frontend/GEMINI.md → Next.js rules
     - backend/GEMINI.md → FastAPI/SQLModel rules

  3. **Monorepo as Single Source of Truth**
     All frontend, backend, and specs must coexist in one repository for Gemini.

  4. **AI Implementation Rules**
     - Follow specs exactly.
     - Never write code not backed by a spec.
     - Update specs if requirements change.
     - Keep file boundaries and folder structure 100% consistent.

  ## Technology Stack Requirements
  ### Frontend
  - Next.js 16+ (App Router)
  - TypeScript
  - Tailwind CSS
  - Better Auth for login/signup
  - JWT tokens stored securely
  - API client in /frontend/lib/api.ts

  ### Backend
  - Python FastAPI
  - SQLModel ORM
  - Neon Serverless PostgreSQL
  - JWT verification from Better Auth token
  - All API routes under `/api/`
  - Filter all queries by authenticated user's user_id

  ### Database
  - tasks table + users table (Better Auth managed)
  - Schema defined in /specs/database/schema.md

  ### Authentication
  - Better Auth (frontend) must issue JWT
  - Backend must verify token with shared secret `BETTER_AUTH_SECRET`
  - All API requests require Authorization: Bearer <token>

  ## API Requirements
  Defined in: /specs/api/rest-endpoints.md

  Endpoints must include:
  - GET /api/{user_id}/tasks
  - POST /api/{user_id}/tasks
  - GET /api/{user_id}/tasks/{id}
  - PUT /api/{user_id}/tasks/{id}
  - DELETE /api/{user_id}/tasks/{id}
  - PATCH /api/{user_id}/tasks/{id}/complete

  All endpoints MUST:
  - Validate JWT
  - Extract user_id from token
  - Ensure ownership of tasks

  ## UI Requirements
  Defined in: /specs/ui/*
  Frontend must include:
  - Login / Signup pages
  - Dashboard (tasks list)
  - Task CRUD UI
  - Responsive design

  ## Required Deliverables
  1. Complete monorepo with all folders above
  2. Updated Phase-2 specs
  3. Fully working backend (FastAPI + SQLModel + JWT)
  4. Fully working frontend (Next.js + Better Auth)
  5. Docker Compose for multi-service local dev
  6. README.md with full instructions

  ## Enforcement
  Gemini CLI must:
  - Follow this constitution strictly
  - Validate file locations
  - Refuse incorrect structure
  - Always reference specs before generating code
response_text: |-
  The project constitution has been updated to version 2.0.0, reflecting the transition to a full-stack web application. The constitution outlines the new monorepo structure, development principles, technology stack requirements (Next.js, FastAPI, PostgreSQL), API requirements, and UI requirements.

  Additionally, the `plan-template.md` and `tasks-template.md` have been adjusted to enforce the new monorepo structure. The `README.md` has been completely rewritten to reflect the Phase II project, including setup and running instructions for local Docker Compose development.
