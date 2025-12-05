--- 
id: 0008
title: Perform non-destructive cross-artifact consistency and quality analysis
stage: general
date: 2025-12-04
surface: agent
model: gemini
feature: 2-fullstack-todo-app
branch: 002-fullstack-todo-app
user: 
command: /sp.analyze Perform a non-destructive cross-artifact consistency and quality analysis across spec.md, plan.md, and tasks.md after task generation.
labels:
  - analysis
  - consistency
  - quality
links:
  spec: D:\Hackhathon 2\hk\project_2\Phase-II-Todo-Full-Stack-Web-Application\specs\002-fullstack-todo-app\spec.md
  plan: D:\Hackhathon 2\hk\project_2\Phase-II-Todo-Full-Stack-Web-Application\specs\002-fullstack-todo-app\plan.md
  tasks: D:\Hackhathon 2\hk\project_2\Phase-II-Todo-Full-Stack-Web-Application\specs\002-fullstack-todo-app\tasks.md
files_yaml: []
tests_yaml: []
---
## Response:

The agent performed a non-destructive cross-artifact consistency and quality analysis across `spec.md`, `plan.md`, and `tasks.md`.

**Key Findings:**
-   **Ambiguity**: Placeholders `[###-feature-name]` were found in `plan.md` and `tasks.md`.
-   **Coverage Gap (CRITICAL)**: Non-functional requirement for GDPR/CCPA compliance and data retention policies for user and task data (1 year max) lacked explicit tasks.
-   **Coverage Gap (HIGH)**: Non-functional requirement for responsive design was not explicitly covered by a task.

The report also includes a detailed Coverage Summary Table, Constitution Alignment Issues (none explicitly found in a conflicting way, but GDPR was missing tasks), Unmapped Tasks (none based on current keyword matching), and Metrics.

**Next Actions:**
CRITICAL issues identified. It is recommended to resolve these issues before proceeding to `/sp.implement`. The user can choose to refine the spec, plan, or tasks to address these.

The agent has also offered to suggest concrete remediation edits.
