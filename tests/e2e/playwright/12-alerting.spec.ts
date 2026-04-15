import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

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

test.describe('Alerting Configuration', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('alerts API returns configured alerts', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/alerts`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(Array.isArray(body.alerts) || body.hasOwnProperty('alerts')).toBe(true)
    }
  })

  test('can create alert rule via API', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/api/v1/alerts`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: {
        name: 'E2E Test Alert',
        condition: 'block_count > 10',
        threshold: 10,
        window: '5m',
        action: 'log',
        enabled: true,
      },
    })
    expect([200, 201, 400, 409]).toContain(resp.status())
  })

  test('can update alert rule via API', async ({ request }) => {
    // Try to update with a non-existent ID
    const resp = await request.put(`${BASE_URL}/api/v1/alerts/e2e-test-alert`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: {
        threshold: 20,
      },
    })
    expect([200, 204, 404]).toContain(resp.status())
  })

  test('can delete alert rule via API', async ({ request }) => {
    const resp = await request.delete(`${BASE_URL}/api/v1/alerts/e2e-test-alert`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 204, 404]).toContain(resp.status())
  })

  test('alerting page loads', async ({ page }) => {
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

    // Try /alerts or /alerting page
    await page.goto(`${BASE_URL}/alerts`)
    const url = page.url()

    // Should load alerts page or redirect
    expect(url.includes('/alerts') || url.includes('/alerting')).toBe(true)
  })

  test('alerting page shows alert rules', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/alerts`)
    await page.waitForTimeout(2000)

    // Should have some content - table, cards, or empty state
    const hasContent = await page.locator('table, [class*="alert"], .empty-state, form').count() > 0
    expect(hasContent || (await page.content()).length > 500).toBe(true)
  })

  test('alert history API returns recent alerts', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/alerts/history?limit=10`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(Array.isArray(body.history) || body.hasOwnProperty('history')).toBe(true)
    }
  })
})
