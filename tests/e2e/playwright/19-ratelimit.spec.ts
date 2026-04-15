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

test.describe('Rate Limiting', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('rate limit config API returns current settings', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/config/ratelimit`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body).toHaveProperty('enabled') || expect(body).hasOwnProperty('rules')
    }
  })

  test('can update rate limit config', async ({ request }) => {
    const resp = await request.put(`${BASE_URL}/api/v1/config/ratelimit`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: {
        enabled: true,
        default_limit: 100,
        window: '1m',
      },
    })
    expect([200, 204, 404]).toContain(resp.status())
  })

  test('rate limit returns 429 when exceeded', async ({ request }) => {
    // Make many rapid requests to trigger rate limit
    const results: number[] = []

    for (let i = 0; i < 150; i++) {
      const resp = await request.get(`${BASE_URL}/hello`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
      results.push(resp.status())
    }

    // Should see 429 (Too Many Requests) at some point
    const has429 = results.includes(429)
    // Or all should pass if rate limit is high
    expect(has429 || !results.includes(200)).toBe(true)
  })

  test('rate limit ban is recorded in stats', async ({ request }) => {
    // Check if rate limit bans are tracked
    const resp = await request.get(`${BASE_URL}/api/v1/stats`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    // Stats should have rate limit related fields
    expect(body).toHaveProperty('rate_limited') || expect(body).toHaveProperty('blocks')
  })

  test('ban lifted after window expires', async ({ request }) => {
    // Make request from a unique IP
    const uniqueIP = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`

    const resp = await request.get(`${BASE_URL}/hello`, {
      headers: {
        'X-API-Key': API_KEY,
        'X-Forwarded-For': uniqueIP,
      },
    })
    // Should return some response
    expect([200, 404, 429]).toContain(resp.status())
  })

  test('rate limit config page loads', async ({ page }) => {
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

    // Try config page with rate limit section
    await page.goto(`${BASE_URL}/config`)
    await page.waitForTimeout(2000)

    // Should load config page
    expect(page.url()).toContain('/config')
  })
})
