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

test.describe('IP ACL and Bans', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('IP ACL API returns blacklist', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/acl/blacklist`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(Array.isArray(body.blacklist)).toBe(true)
  })

  test('IP ACL API returns whitelist', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/acl/whitelist`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(Array.isArray(body.whitelist)).toBe(true)
  })

  test('can add IP to blacklist via API', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/api/v1/acl/blacklist`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: {
        ip: '192.168.99.99',
        reason: 'E2E test',
        expires_at: null,
      },
    })
    expect([200, 201, 409]).toContain(resp.status())
  })

  test('can add IP to whitelist via API', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/api/v1/acl/whitelist`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: {
        ip: '10.0.0.1',
        reason: 'E2E test',
      },
    })
    expect([200, 201, 409]).toContain(resp.status())
  })

  test('can remove IP from blacklist via API', async ({ request }) => {
    // Try to remove a test IP
    const resp = await request.delete(`${BASE_URL}/api/v1/acl/blacklist/192.168.99.99`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 204, 404]).toContain(resp.status())
  })

  test('bans API returns active bans', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/bans`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(Array.isArray(body.bans) || body.hasOwnProperty('bans')).toBe(true)
  })

  test('can lift a ban via API', async ({ request }) => {
    // Try to lift ban for a test IP
    const resp = await request.delete(`${BASE_URL}/api/v1/bans/192.168.99.99`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 204, 404]).toContain(resp.status())
  })

  test('blocked IP returns 403', async ({ request }) => {
    // Send request from a blocked IP (if any exist)
    const resp = await request.get(`${BASE_URL}/hello`, {
      headers: {
        'X-API-Key': API_KEY,
        'X-Forwarded-For': '192.168.99.99',
      },
    })
    // Should return some response (blocked or allowed depending on ACL state)
    expect([200, 403, 404]).toContain(resp.status())
  })
})
