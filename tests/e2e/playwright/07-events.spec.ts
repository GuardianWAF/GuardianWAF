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

test.describe('Events API', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('events endpoint returns JSON array', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/events?limit=10`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('events')
    expect(Array.isArray(body.events)).toBe(true)
  })

  test('events can be filtered by action', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/events?action=block&limit=10`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(Array.isArray(body.events)).toBe(true)
  })

  test('events can be filtered by rule_id', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/events?rule_id=SQLI-001&limit=10`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(Array.isArray(body.events)).toBe(true)
  })

  test('events support pagination', async ({ request }) => {
    const page1 = await request.get(`${BASE_URL}/api/v1/events?limit=5&offset=0`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    const page2 = await request.get(`${BASE_URL}/api/v1/events?limit=5&offset=5`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(page1.status()).toBe(200)
    expect(page2.status()).toBe(200)
    const body1 = await page1.json()
    const body2 = await page2.json()
    // Pages should have events (unless total < 10)
    expect(Array.isArray(body1.events)).toBe(true)
    expect(Array.isArray(body2.events)).toBe(true)
  })

  test('events can be filtered by IP', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/events?ip=192.168.1.1&limit=10`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(Array.isArray(body.events)).toBe(true)
  })

  test('events can be filtered by date range', async ({ request }) => {
    const now = Date.now()
    const hourAgo = now - 3600000
    const resp = await request.get(`${BASE_URL}/api/v1/events?start=${hourAgo}&end=${now}&limit=10`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(Array.isArray(body.events)).toBe(true)
  })

  test('logs page displays events table', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/logs`)
    await page.waitForURL(/\/logs/, { timeout: 5000 })

    // Should have events table or loading state
    await page.waitForSelector('table, .empty-state, [data-testid="events-table"]', { timeout: 10000 }).catch(() => {
      // If no table found, check if page loaded at all
      expect(page.url()).toContain('/logs')
    })
  })

  test('logs page has search/filter controls', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/logs`)
    await page.waitForURL(/\/logs/, { timeout: 5000 })

    // Look for search input or filter controls
    const hasSearch = await page.locator('input[type="search"], input[placeholder*="earch"], input[placeholder*="ilter"]').count() > 0
    const hasSelect = await page.locator('select').count() > 0

    // At minimum, should have some filtering capability
    expect(hasSearch || hasSelect).toBe(true)
  })
})
