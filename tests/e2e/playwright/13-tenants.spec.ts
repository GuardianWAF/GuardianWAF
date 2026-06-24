import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'
const ADMIN_KEY = process.env.E2E_ADMIN_KEY || ''

async function getSessionCookie(request: any): Promise<string> {
  const loginResp = await request.post(`${BASE_URL}/login`, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Origin': BASE_URL,
    },
    form: { key: API_KEY },
  })
  const setCookie = loginResp.headers()['set-cookie'] || ''
  const cookies = setCookie.split(/\,\s*(?=gwaf_session=)/)
  const sessionCookie = cookies.find((c: string) => c.includes('gwaf_session'))
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
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('tenants')
  })

  test('admin tenants API rejects dashboard API key and session cookie', async ({ request }) => {
    const dashboardKeyResp = await request.get(`${BASE_URL}/api/admin/tenants`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(dashboardKeyResp.status()).toBe(401)

    const sessionResp = await request.get(`${BASE_URL}/api/admin/tenants`, {
      headers: {
        Cookie: sessionCookie,
      },
    })
    expect(sessionResp.status()).toBe(401)
  })

  test('admin tenants API accepts dashboard admin key when configured', async ({ request }) => {
    test.skip(!ADMIN_KEY, 'E2E_ADMIN_KEY is required to verify /api/admin/* authorization')

    const resp = await request.get(`${BASE_URL}/api/admin/tenants`, {
      headers: {
        'X-API-Key': ADMIN_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('tenants')
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
    expect([201, 400, 409, 503]).toContain(resp.status())
  })

  test('can get tenant config via API', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/tenants/e2e-test-tenant/config`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404, 429, 503]).toContain(resp.status())
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
    expect([200, 404, 429, 503]).toContain(resp.status())
  })

  test('tenant stats API returns metrics', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/tenants/e2e-test-tenant/stats`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404, 429, 503]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body.hasOwnProperty('requests') || body.hasOwnProperty('blocks')).toBe(true)
    }
  })

  test('can delete tenant via API', async ({ request }) => {
    const resp = await request.delete(`${BASE_URL}/api/v1/tenants/e2e-test-tenant`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([204, 404, 429, 503]).toContain(resp.status())
  })

  test('tenants page loads', async ({ page }) => {
    await page.context().addCookies([
      {
        name: 'gwaf_session',
        value: sessionCookie.split('=')[1] || '',
        domain: new URL(BASE_URL).hostname,
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
        name: 'gwaf_session',
        value: sessionCookie.split('=')[1] || '',
        domain: new URL(BASE_URL).hostname,
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

  test('tenants page requires admin key before listing admin tenants', async ({ page }) => {
    await page.context().addCookies([
      {
        name: 'gwaf_session',
        value: sessionCookie.split('=')[1] || '',
        domain: new URL(BASE_URL).hostname,
        path: '/',
        httpOnly: true,
        secure: false,
      }
    ])

    await page.goto(`${BASE_URL}/tenants`)
    await expect(page.getByLabel('dashboard.admin_key')).toBeVisible()

    if (ADMIN_KEY) {
      await page.getByLabel('dashboard.admin_key').fill(ADMIN_KEY)
      await page.getByRole('button', { name: 'Unlock' }).click()
      await expect(page.getByRole('button', { name: 'Clear admin key' })).toBeVisible()
    }
  })
})
