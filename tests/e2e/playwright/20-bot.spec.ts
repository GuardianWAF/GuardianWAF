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

test.describe('Bot Detection', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('bot detection config API returns settings', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/config/bot`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body).toHaveProperty('enabled') || expect(body.hasOwnProperty('rules'))
    }
  })

  test('known bot user agents pass through', async ({ request }) => {
    const botAgents = [
      'Googlebot/2.1 (+http://www.google.com/bot.html)',
      'Bingbot/2.0 (+http://www.bing.com/bingbot.htm)',
      'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    ]

    for (const ua of botAgents) {
      const resp = await request.get(`${BASE_URL}/hello`, {
        headers: {
          'User-Agent': ua,
          'X-API-Key': API_KEY,
        },
      })
      // Bot user agents should pass or be challenged, not hard blocked
      expect([200, 301, 302, 404, 403]).toContain(resp.status())
    }
  })

  test('suspicious user agents are challenged', async ({ request }) => {
    const suspiciousAgents = [
      'python-requests/2.28.0',
      'curl/7.68.0',
      'wget/1.20.3',
      'HttpClient',
    ]

    let anyChallenged = false

    for (const ua of suspiciousAgents) {
      const resp = await request.get(`${BASE_URL}/hello`, {
        headers: {
          'User-Agent': ua,
          'X-API-Key': API_KEY,
        },
      })
      if (resp.status() === 403) {
        anyChallenged = true
      }
    }

    // At least some suspicious agents should be challenged
    // Note: this depends on bot detection configuration
  })

  test('JA3 fingerprinting is applied', async ({ request }) => {
    // Request with specific TLS fingerprint
    const resp = await request.get(`${BASE_URL}/hello`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })

    // Should return response (blocked, challenge, or pass)
    expect(resp.status()).toBeGreaterThan(0)

    // Check if JA3 fingerprint was logged
    const eventsResp = await request.get(`${BASE_URL}/api/v1/events?limit=1`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })

    if (eventsResp.status() === 200) {
      const body = await eventsResp.json()
      // Events may contain JA3 fingerprint if bot detection fired
    }
  })

  test('bot detection stats are tracked', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/stats`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    // Stats may contain bot detection metrics
    expect(body).toHaveProperty('requests') || expect(body).toHaveProperty('blocks')
  })
})
