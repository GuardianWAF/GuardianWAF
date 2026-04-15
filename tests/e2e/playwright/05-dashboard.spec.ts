import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

// Helper to authenticate and get session cookie
async function getSessionCookie(request: any): Promise<string> {
  const loginResp = await request.post(`${BASE_URL}/login`, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Origin': BASE_URL,
    },
    form: { key: API_KEY },
  })
  const cookies = loginResp.headers()['set-cookie'] || []
  const sessionCookie = cookies.find((c: string) => c.includes('session'))
  return sessionCookie?.split(';')[0] || ''
}

test.describe('Dashboard UI Pages', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('logs page loads', async ({ page }) => {
    await page.context().addCookies([
      {
        name: 'session',
        value: sessionCookie.split('=')[1] || '',
        domain: 'localhost',
        path: '/',
        httpOnly: true,
        secure: false, // http for localhost
      }
    ])

    await page.goto(`${BASE_URL}/logs`)
    // Should not redirect to login
    await page.waitForURL(/\/logs/, { timeout: 5000 }).catch(() => {
      // If we're still on login, fail
      expect(page.url()).toContain('/logs')
    })
  })

  test('config page loads', async ({ page }) => {
    await page.context().addCookies([
      {
        name: 'session',
        value: sessionCookie.split('=')[1] || '',
        domain: 'localhost',
        path: '/',
        httpOnly: true,
        secure: false,
      }
    ])

    await page.goto(`${BASE_URL}/config`)
    await page.waitForURL(/\/config/, { timeout: 5000 }).catch(() => {
      expect(page.url()).toContain('/config')
    })
  })

  test('rules page loads', async ({ page }) => {
    await page.context().addCookies([
      {
        name: 'session',
        value: sessionCookie.split('=')[1] || '',
        domain: 'localhost',
        path: '/',
        httpOnly: true,
        secure: false,
      }
    ])

    await page.goto(`${BASE_URL}/rules`)
    await page.waitForURL(/\/rules/, { timeout: 5000 }).catch(() => {
      expect(page.url()).toContain('/rules')
    })
  })

  test('routing page loads', async ({ page }) => {
    await page.context().addCookies([
      {
        name: 'session',
        value: sessionCookie.split('=')[1] || '',
        domain: 'localhost',
        path: '/',
        httpOnly: true,
        secure: false,
      }
    ])

    await page.goto(`${BASE_URL}/routing`)
    await page.waitForURL(/\/routing/, { timeout: 5000 }).catch(() => {
      expect(page.url()).toContain('/routing')
    })
  })

  test('AI page loads', async ({ page }) => {
    await page.context().addCookies([
      {
        name: 'session',
        value: sessionCookie.split('=')[1] || '',
        domain: 'localhost',
        path: '/',
        httpOnly: true,
        secure: false,
      }
    ])

    await page.goto(`${BASE_URL}/ai`)
    await page.waitForURL(/\/ai/, { timeout: 5000 }).catch(() => {
      expect(page.url()).toContain('/ai')
    })
  })
})
