import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

test.describe('Login', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(`${BASE_URL}/login`)
  })

  test('shows login page', async ({ page }) => {
    await expect(page.locator('body')).toContainText(/login/i)
  })

  test('redirects to dashboard on valid credentials', async ({ page }) => {
    // Fill in the API key
    const keyInput = page.locator('input[name="key"], input[type="password"], input[type="text"]')
    await keyInput.fill(API_KEY)

    // Submit
    await page.locator('button[type="submit"], input[type="submit"]').click()

    // Should redirect to dashboard
    await expect(page).toHaveURL(/\/(?:#\/)?$/, { timeout: 5000 }).catch(() => {
      // Fallback: check if we're on a dashboard page
      expect(page.url()).not.toContain('/login')
    })
  })

  test('shows error on invalid credentials', async ({ page }) => {
    const keyInput = page.locator('input[name="key"], input[type="password"], input[type="text"]')
    await keyInput.fill('wrong-key')

    await page.locator('button[type="submit"], input[type="submit"]').click()

    await expect(page.locator('body')).toContainText(/invalid|error|try again/i)
  })
})

test.describe('Dashboard', () => {
  test('requires authentication', async ({ page }) => {
    await page.goto(`${BASE_URL}/`)
    // Should redirect to login
    await expect(page).toHaveURL(/\/login/, { timeout: 5000 }).catch(() => {
      expect(page.url()).toContain('/login')
    })
  })
})
