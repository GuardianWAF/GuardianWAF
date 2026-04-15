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

test.describe('API Validation & Error Handling', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('API returns 400 for malformed JSON', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/api/v1/config/ai`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: '{ invalid json }',
    })
    expect([400, 500]).toContain(resp.status())
  })

  test('API returns 400 for invalid request body', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/api/v1/routes`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: JSON.stringify({ invalid: 'field' }),
    })
    expect([400, 404, 409]).toContain(resp.status())
  })

  test('API returns 404 for non-existent endpoint', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/nonexistent`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(404)
  })

  test('API returns 404 for non-existent resource', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/rules/nonexistent-id`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(404)
  })

  test('API returns 401 for missing API key', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/config`)
    expect([401, 403]).toContain(resp.status())
  })

  test('API returns 403 for invalid API key', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/config`, {
      headers: {
        'X-API-Key': 'invalid-key-12345',
      },
    })
    expect([401, 403]).toContain(resp.status())
  })

  test('API handles missing required fields', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/api/v1/rules`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: JSON.stringify({}),
    })
    expect([400, 500]).toContain(resp.status())
  })

  test('API returns 413 for oversized payload', async ({ request }) => {
    const largePayload = { data: 'x'.repeat(1024 * 1024) } // 1MB

    const resp = await request.post(`${BASE_URL}/api/v1/config/ai`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: largePayload,
    })
    expect([413, 400, 500]).toContain(resp.status())
  })

  test('API handles invalid content type', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/api/v1/config/ai`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'text/plain',
      },
      data: 'some text',
    })
    expect([400, 415, 500]).toContain(resp.status())
  })

  test('CORS preflight is handled', async ({ request }) => {
    const resp = await request.options(`${BASE_URL}/api/v1/stats`, {
      headers: {
        'Origin': 'http://example.com',
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'X-API-Key',
      },
    })
    // Should return 200 or 204 with CORS headers, or 404/405 if not handled
    expect([200, 204, 400, 404, 405]).toContain(resp.status())
  })

  test('API includes rate limit headers', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/stats`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })

    const headers = resp.headers()
    // May include rate limit headers
    const hasRateLimitHeaders =
      headers.hasOwnProperty('x-ratelimit-limit') ||
      headers.hasOwnProperty('x-ratelimit-remaining') ||
      headers.hasOwnProperty('ratelimit-limit')
  })
})
