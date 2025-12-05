<!--
Sync Impact Report:
- Version change: 1.0.0 -> 2.0.0
- Modified principles: Complete overhaul of principles.
- Added sections: Purpose, Project Evolution, Monorepo Structure, Development Principles, Technology Stack Requirements, API Requirements, UI Requirements, Required Deliverables, Enforcement.
- Removed sections: All old sections replaced.
- Templates requiring updates:
  - ✅ .specify/templates/plan-template.md
  - ✅ .specify/templates/tasks-template.md
  - ✅ README.md
- Follow-up TODOs: None.
-->
# Spec-Kit Constitution for Phase II: Full-Stack Todo Web Application

## Governance
- **CONSTITUTION_VERSION**: 2.0.0
- **RATIFICATION_DATE**: 2025-12-04
- **LAST_AMENDED_DATE**: 2025-12-04

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
