// e2e-tests/example.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Todo App E2E Tests', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the app before each test
    await page.goto('http://localhost:3000/');
  });

  test('should allow a user to register, login, and create a task', async ({ page }) => {
    // 1. Registration
    await page.goto('http://localhost:3000/register');
    await page.fill('input[name="username"]', 'e2euser');
    await page.fill('input[name="email"]', 'e2e@example.com');
    await page.fill('input[name="password"]', 'Password123!');
    await page.click('button[type="submit"]');
    
    // Should be redirected to the dashboard after registration
    await expect(page).toHaveURL('http://localhost:3000/dashboard');

    // 2. Logout
    await page.click('button:has-text("Logout")');
    await expect(page).toHaveURL('http://localhost:3000/login');

    // 3. Login
    await page.fill('input[name="username"]', 'e2euser');
    await page.fill('input[name="password"]', 'Password123!');
    await page.click('button[type="submit"]');

    // Should be redirected to the dashboard after login
    await expect(page).toHaveURL('http://localhost:3000/dashboard');

    // 4. Create a task
    await page.fill('input[id="title"]', 'My E2E Test Task');
    await page.fill('textarea[id="description"]', 'This is an E2E test task.');
    await page.click('button:has-text("Create Task")');

    // Expect the new task to be visible on the page
    await expect(page.locator('h3:has-text("My E2E Test Task")')).toBeVisible();
    await expect(page.locator('p:has-text("This is an E2E test task.")')).toBeVisible();
  });
});
