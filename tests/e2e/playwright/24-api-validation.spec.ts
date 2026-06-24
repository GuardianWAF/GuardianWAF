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

async function responseJSON(resp: any): Promise<any> {
  const text = await resp.text()
  return text ? JSON.parse(text) : {}
}

test.describe('API Validation & Error Handling', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('API returns 400 for malformed JSON', async ({ request }) => {
    const resp = await request.put(`${BASE_URL}/api/v1/routing`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: '{ invalid json }',
    })
    expect(resp.status()).toBe(400)
    const body = await responseJSON(resp)
    expect(String(body.error || '')).toMatch(/invalid JSON/i)
  })

  test('API returns 400 for invalid request body', async ({ request }) => {
    const resp = await request.put(`${BASE_URL}/api/v1/routing`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: JSON.stringify({ invalid: 'field' }),
    })
    expect(resp.status()).toBe(400)
    const body = await responseJSON(resp)
    expect(String(body.error || '')).toMatch(/at least one/i)
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
    expect(resp.status()).toBe(400)
    const body = await responseJSON(resp)
    expect(String(body.error || '')).toBeTruthy()
  })

  test('API returns 413 for oversized payload', async ({ request }) => {
    const largePayload = { data: 'x'.repeat(1024 * 1024) } // 1MB

    const resp = await request.put(`${BASE_URL}/api/v1/routing`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: largePayload,
    })
    expect(resp.status()).toBe(413)
    const body = await responseJSON(resp)
    expect(String(body.error || '')).toMatch(/too large/i)
  })

  test('API handles invalid content type', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/api/v1/geoip/lookup`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'text/plain',
      },
      data: '{"ip":"1.2.3.4"}',
    })
    expect(resp.status()).toBe(415)
    const body = await responseJSON(resp)
    expect(String(body.error || '')).toMatch(/Content-Type/i)
  })

  test('CORS preflight is handled', async ({ request }) => {
    const resp = await request.fetch(`${BASE_URL}/api/v1/stats`, {
      method: 'OPTIONS',
      headers: {
        'Origin': 'http://example.com',
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'X-API-Key',
      },
    })
    expect(resp.status()).toBe(204)
  })

  test('API includes rate limit headers', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/stats`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })

    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('total_requests')
    expect(body).toHaveProperty('blocked_requests')
  })
})
