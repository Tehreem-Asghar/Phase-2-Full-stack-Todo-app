# Research Findings for Full-Stack Todo Web Application

## 1. Technology Versions

### Next.js Version
- **Decision**: Next.js v16.0.6
- **Rationale**: This is the latest stable version (as of 2025-11-30) and includes significant improvements like Cache Components, stable Turbopack, React Compiler support, and enhanced routing. Opting for the latest stable version ensures access to the newest features, performance optimizations, and long-term support.
- **Alternatives Considered**: Earlier versions of Next.js (e.g., v15) were considered but rejected due to the benefits provided by the latest stable release.

### FastAPI Version
- **Decision**: FastAPI v0.123.5
- **Rationale**: This is the latest stable version (as of 2025-12-02). While still in the 0.x.x range, FastAPI is considered production-ready. Using the latest version ensures access to recent bug fixes, performance improvements, and new features.
- **Alternatives Considered**: No specific alternatives were considered, as FastAPI is mandated by the constitution.

---

## 2. Backend Dependencies (FastAPI)

### JWT Handling
- **Decision**: `python-jose` and `passlib`
- **Rationale**: FastAPI provides excellent support for implementing authentication using OAuth2 with Bearer tokens, which commonly use JWTs. `python-jose` is widely used with FastAPI for JWT encoding/decoding and verification, while `passlib` is essential for secure password hashing and verification. This combination provides a robust and well-integrated solution for authentication.
- **Alternatives Considered**: `PyJWT` (core JWT library) and `Authlib` (more comprehensive OAuth/OpenID). `python-jose` was chosen for its direct integration with FastAPI's security utilities and its ability to handle both JWTs and password hashing effectively for this project's scope.

### Database Driver (PostgreSQL)
- **Decision**: `psycopg` (Psycopg3)
- **Rationale**: `psycopg` is the modern, asynchronous-ready PostgreSQL adapter for Python. As FastAPI is an asynchronous framework and SQLModel supports asynchronous operations, `psycopg` is the most suitable choice for optimal performance and compatibility with the application's design.
- **Alternatives Considered**: `psycopg2` (synchronous, older) and `asyncpg` (highly efficient but a separate library). `psycopg` offers a good balance of modern features, `asyncio` support, and a direct evolutionary path from the widely-used `psycopg2`.

### Validation
- **Decision**: `Pydantic` (already integral)
- **Rationale**: SQLModel is built on Pydantic, leveraging Python type hints for automatic data validation, serialization, and deserialization. FastAPI also utilizes Pydantic for request and response body validation. Given its seamless integration and robust features, no additional validation library is necessary.
- **Alternatives Considered**: None, as Pydantic is a core component of the chosen backend stack.

---

## 3. Frontend E2E Testing Framework

### E2E Testing Framework (Next.js)
- **Decision**: `Playwright`
- **Rationale**: Playwright offers excellent cross-browser testing capabilities (Chromium, Firefox, WebKit) with a single API, which is crucial for ensuring broad compatibility. Its modern features, reliable execution, and strong community support make it a robust choice for E2E testing in Next.js applications.
- **Alternatives Considered**: `Cypress`. While Cypress is also popular and interactive, Playwright's comprehensive cross-browser support and slightly better performance for larger test suites make it a preferred choice for this project.
