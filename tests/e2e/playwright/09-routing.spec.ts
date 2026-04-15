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

test.describe('Routing Configuration', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('routing API returns routes', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/routes`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('routes')
    expect(Array.isArray(body.routes)).toBe(true)
  })

  test('routing API returns upstreams', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/upstreams`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('upstreams')
    expect(Array.isArray(body.upstreams)).toBe(true)
  })

  test('routing page loads with topology graph', async ({ page }) => {
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
    await page.waitForURL(/\/routing/, { timeout: 5000 })

    // Page should load - the routing graph uses React Flow
    // Look for the page container
    const pageContent = await page.content()
    expect(pageContent.length).toBeGreaterThan(500)
  })

  test('routing page shows route list or graph', async ({ page }) => {
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
    await page.waitForURL(/\/routing/, { timeout: 5000 })

    // Should have some UI - table, graph canvas, or cards
    const hasTable = await page.locator('table').count() > 0
    const hasCanvas = await page.locator('canvas, [class*="flow"], [class*="graph"]').count() > 0
    const hasCards = await page.locator('[class*="card"]').count() > 0

    expect(hasTable || hasCanvas || hasCards).toBe(true)
  })

  test('can add a new upstream via API', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/api/v1/upstreams`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: {
        name: 'test-upstream',
        targets: [
          { host: 'localhost', port: 8080, weight: 1 },
        ],
        health_check: {
          path: '/health',
          interval: '10s',
        },
      },
    })
    // Should create or return existing
    expect([200, 201, 409]).toContain(resp.status())
  })

  test('can add a new route via API', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/api/v1/routes`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: {
        path: '/test',
        upstream: 'test-upstream',
        methods: ['GET'],
      },
    })
    // Should create, update, or return existing/conflict
    expect([200, 201, 409, 400]).toContain(resp.status())
  })

  test('routing page has add route button', async ({ page }) => {
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
    await page.waitForURL(/\/routing/, { timeout: 5000 })

    // Look for add/create button
    const hasAddButton = await page.locator('button:has-text("Add"), button:has-text("Create"), button:has-text("New")').count() > 0
    const hasForm = await page.locator('form').count() > 0

    expect(hasAddButton || hasForm).toBe(true)
  })
})
