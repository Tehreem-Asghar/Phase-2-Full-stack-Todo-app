---
id: 0002
title: Create Phase 1 Constitution
stage: constitution
date: 2025-12-03
surface: agent
model: gemini-1.5-flash
feature: none
branch: [BRANCH]
user: [USER]
command: /sp.constitution Create a constitution for Phase 1 of my project...
labels: ["constitution", "principles", "phase-1"]
links:
  spec: null
  ticket: null
  adr: null
  pr: null
files:
  - .specify/memory/constitution.md
tests:
  - null
---

## Prompt

/sp.constitution Create a constitution for Phase 1 of my project.

This constitution must enforce the following rules:

1. Project Scope
   - This phase is only for an in-memory Python Todo CLI application.
   - No database, no web server, no API, no frameworks.
   - Only pure Python logic organized cleanly.

2. Architecture Rules
   - Use a simple Python project structure:
       /models      → Task model only
       /services    → TaskService with add, view, update, delete, complete
       main.py      → CLI loop only
   - All business logic must remain inside services, not in main.py.
   - No external dependencies except Python standard library.

3. Coding Standards
   - Use Python 3.13+ type hints everywhere.
   - Write readable, clean, beginner-friendly Python code.
   - Use English comments for clarity.
   - No unnecessary complexity.
   - Functions must be small and single-purpose.

4. CLI Rules
   - CLI must support the following commands:
       add <task-title>
       update <id> <new-title>
       delete <id>
       complete <id>
       view
       exit
   - CLI must give clear error messages for invalid input.
   - Do not use external CLI libs — only input() and print().

5. Spec-Kit Compatibility
   - AI must always follow the specs inside /specs/ folder.
   - If any conflict occurs, the spec has higher priority than the constitution.
   - All generated code must map 1-to-1 with the Phase 1 specs.

6. Output Rules
   - Never generate code outside the boundaries of Phase 1.
   - Never introduce future-phase features like database, APIs, or UI.
   - Keep everything minimal, predictable, and spec-driven.

7. Behavior Rules for AI Agent
   - Always ask before adding new files.
   - Always follow "single responsibility per file" principle.
   - Never assume future architecture — stick strictly to Phase 1.

Create this constitution in a strict, actionable, rule-based format.

## Response snapshot

Constitution updated to v2.0.0.

## Outcome

- ✅ Impact: Constitution updated to v2.0.0 with new principles for Phase 1.
- 🧪 Tests: No tests were run as part of this operation.
- 📁 Files: .specify/memory/constitution.md was modified.
- 🔁 Next prompts: The user should now consider updating dependent templates and documentation files as listed in the Sync Impact Report.
- 🧠 Reflection: The user provided a detailed set of rules which were translated into a new version of the constitution.

## Evaluation notes (flywheel)

- Failure modes observed: None
- Graders run and results (PASS/FAIL): null
- Prompt variant (if applicable): null
- Next experiment (smallest change to try): null
