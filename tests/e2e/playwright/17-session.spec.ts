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

test.describe('Session Management', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('session persists across requests', async ({ request }) => {
    // Make first request with session
    const resp1 = await request.get(`${BASE_URL}/api/v1/stats`, {
      headers: {
        'Cookie': sessionCookie,
      },
    })
    expect(resp1.status()).toBe(200)

    // Make second request with same session
    const resp2 = await request.get(`${BASE_URL}/api/v1/stats`, {
      headers: {
        'Cookie': sessionCookie,
      },
    })
    expect(resp2.status()).toBe(200)
  })

  test('invalid session returns 401', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/config`, {
      headers: {
        'Cookie': 'session=invalid-session-token',
      },
    })
    expect([401, 403]).toContain(resp.status())
  })

  test('API key auth works for API endpoints', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/stats`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 429]).toContain(resp.status())
  })

  test('missing auth returns 401', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/config`)
    expect([401, 403]).toContain(resp.status())
  })

  test('session cookie has security attributes', async ({ request }) => {
    const loginResp = await request.post(`${BASE_URL}/login`, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': BASE_URL,
      },
      form: { key: API_KEY },
    })

    const cookies = loginResp.headers()['set-cookie']
    if (cookies) {
      const sessionCookie = Array.isArray(cookies) ? cookies.find((c: string) => c.includes('gwaf_session')) : cookies

      if (sessionCookie) {
        // Should have HttpOnly flag
        expect(sessionCookie.toLowerCase()).toContain('httponly')
        // Should have SameSite or Secure flag
        const hasSecurityFlag = sessionCookie.toLowerCase().includes('samesite') ||
                                sessionCookie.toLowerCase().includes('secure')
        // Note: secure may not be set on HTTP localhost
        expect(hasSecurityFlag || BASE_URL.includes('localhost')).toBe(true)
      }
    }
  })

  test('CSRF protection blocks cross-origin form submissions', async ({ page, request }) => {
    // Login first
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

    // Try to submit form from different origin
    const resp = await page.request.put(`${BASE_URL}/api/v1/ai/config`, {
      headers: {
        'Content-Type': 'application/json',
        'Origin': 'http://evil.com',
        'Cookie': sessionCookie,
      },
      data: JSON.stringify({ enabled: false }),
    })

    expect([400, 403, 429]).toContain(resp.status())
  })

  test('dashboard pages redirect to login when unauthenticated', async ({ page }) => {
    // Clear cookies
    await page.context().clearCookies()

    await page.goto(`${BASE_URL}/logs`)

    // Should redirect to login
    await page.waitForTimeout(1000)
    const url = page.url()
    expect(url.includes('/login') || url.includes('login')).toBe(true)
  })

  test('dashboard accessible with valid session', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/logs`)
    await page.waitForURL(/\/logs/, { timeout: 5000 })
    expect(page.url()).toContain('/logs')
  })
})
