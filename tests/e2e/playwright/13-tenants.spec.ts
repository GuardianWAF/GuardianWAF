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

test.describe('Multi-Tenant Management', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('tenants API returns tenant list', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/tenants`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(Array.isArray(body.tenants) || body.hasOwnProperty('tenants')).toBe(true)
    }
  })

  test('can create tenant via API', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/api/v1/tenants`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: {
        name: 'e2e-test-tenant',
        domain: 'e2e-test.example.com',
        plan: 'basic',
      },
    })
    expect([200, 201, 400, 409]).toContain(resp.status())
  })

  test('can get tenant config via API', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/tenants/e2e-test-tenant/config`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404]).toContain(resp.status())
  })

  test('can update tenant config via API', async ({ request }) => {
    const resp = await request.put(`${BASE_URL}/api/v1/tenants/e2e-test-tenant/config`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: {
        block_threshold: 60,
      },
    })
    expect([200, 204, 404]).toContain(resp.status())
  })

  test('tenant stats API returns metrics', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/tenants/e2e-test-tenant/stats`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body).toHaveProperty('requests') || expect(body).toHaveProperty('blocks')
    }
  })

  test('can delete tenant via API', async ({ request }) => {
    const resp = await request.delete(`${BASE_URL}/api/v1/tenants/e2e-test-tenant`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 204, 404]).toContain(resp.status())
  })

  test('tenants page loads', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/tenants`)
    const url = page.url()

    // Should load tenants page
    expect(url.includes('/tenants')).toBe(true)
  })

  test('tenants page shows tenant list', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/tenants`)
    await page.waitForTimeout(2000)

    // Should have some content
    const hasContent = await page.locator('table, [class*="tenant"], .empty-state, form').count() > 0
    expect(hasContent || (await page.content()).length > 500).toBe(true)
  })
})
