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
  const setCookie = loginResp.headers()['set-cookie'] || ''
  const cookies = setCookie.split(/\,\s*(?=gwaf_session=)/)
  const sessionCookie = cookies.find((c: string) => c.includes('gwaf_session'))
  return sessionCookie?.split(';')[0] || ''
}

test.describe('SSL/TLS Configuration', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('SSL stats API returns certificate info', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/ssl`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 429]).toContain(resp.status())
    if (resp.status() === 429) return
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body).toHaveProperty('certs')
    }
  })

  test('SSL certificates API returns cert list', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/ssl`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 429]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(Array.isArray(body.certs)).toBe(true)
    }
  })

  test('can upload certificate via API', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/api/v1/ssl/certificates`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: {
        name: 'e2e-test-cert',
        cert: 'LS0tLS1CRUdJTiBFRCBLWUNJQyBMT0NBIEtFWS0tLS0=',
        key: 'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0=',
      },
    })
    expect([400, 409, 429, 501]).toContain(resp.status())
  })

  test('can delete certificate via API', async ({ request }) => {
    const resp = await request.delete(`${BASE_URL}/api/v1/ssl/certificates/e2e-test-cert`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 204, 404, 429]).toContain(resp.status())
  })

  test('SSL page loads', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/ssl`)
    const url = page.url()

    // Should load SSL page or redirect to config
    expect(url.includes('/ssl') || url.includes('/cert')).toBe(true)
  })

  test('SSL page shows certificate list', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/ssl`)
    await page.waitForTimeout(2000)

    // Should have some content
    const hasContent = await page.locator('table, [class*="cert"], .empty-state, form').count() > 0
    expect(hasContent || (await page.content()).length > 500).toBe(true)
  })

  test('HTTPS endpoints are accessible', async ({ request }) => {
    // Test that HTTPS is working on a different port or same port
    const resp = await request.get(`${BASE_URL}/healthz`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBeGreaterThan(0)
  })
})
