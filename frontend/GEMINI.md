# Gemini CLI Rules - Frontend

This `GEMINI.md` file provides specific guidelines and context for working with the frontend of this project.

## Overview

The frontend is a Next.js application that provides the user interface for the Todo Full-Stack Web Application. It handles user interactions, displays tasks, and communicates with the backend API.

## Technology Stack

*   **Framework**: Next.js
*   **Library**: React
*   **Language**: TypeScript
*   **Styling**: Tailwind CSS
*   **Package Manager**: npm/yarn/pnpm/bun (as per `package.json` scripts)

## Setup

1.  **Install Dependencies**:
    Navigate to the `frontend` directory and install the required packages.

    ```bash
    cd frontend
    npm install
    # or yarn install
    # or pnpm install
    # or bun install
    ```

## Running the Application

To start the Next.js development server:

```bash
cd frontend
npm run dev
# or yarn dev
# or pnpm dev
# or bun dev
```

The application will typically be available at `http://localhost:3000`.

## Key Components and Structure

*   `src/app/`: Contains the main application routes and pages.
*   `components/`: Reusable React components such as `Navbar.tsx`, `TaskFilter.tsx`, `TaskForm.tsx`, `TaskItem.tsx`, and `TaskList.tsx`.
*   `lib/`: Utility functions and client-side logic, e.g., `auth.ts` for authentication related functionalities.
*   `public/`: Static assets.