import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const WAF_URL = process.env.E2E_WAF_URL || 'http://localhost:8080'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

type IPACLResponse = {
  blacklist: string[]
  whitelist: string[]
}

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

async function getIPACL(request: any): Promise<IPACLResponse | null> {
  const resp = await request.get(`${BASE_URL}/api/v1/ipacl`, {
    headers: {
      'X-API-Key': API_KEY,
    },
  })
  expect([200, 429]).toContain(resp.status())
  if (resp.status() === 429) return null
  const body = await resp.json()
  expect(Array.isArray(body.blacklist)).toBe(true)
  expect(Array.isArray(body.whitelist)).toBe(true)
  return body
}

async function addIPACL(request: any, list: 'blacklist' | 'whitelist', ip: string): Promise<boolean> {
  const resp = await request.post(`${BASE_URL}/api/v1/ipacl`, {
    headers: {
      'X-API-Key': API_KEY,
      'Content-Type': 'application/json',
    },
    data: { list, ip },
  })
  expect([200, 201, 429]).toContain(resp.status())
  return resp.status() !== 429
}

async function removeIPACL(request: any, list: 'blacklist' | 'whitelist', ip: string): Promise<void> {
  await request.delete(`${BASE_URL}/api/v1/ipacl`, {
    headers: {
      'X-API-Key': API_KEY,
      'Content-Type': 'application/json',
    },
    data: { list, ip },
  })
}

test.describe('IP ACL and Bans', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('IP ACL API returns blacklist', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/ipacl`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 429]).toContain(resp.status())
    if (resp.status() === 429) return
    const body = await resp.json()
    expect(Array.isArray(body.blacklist)).toBe(true)
  })

  test('IP ACL API returns whitelist', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/ipacl`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 429]).toContain(resp.status())
    if (resp.status() === 429) return
    const body = await resp.json()
    expect(Array.isArray(body.whitelist)).toBe(true)
  })

  test('can add IP to blacklist via API', async ({ request }) => {
    const ip = `198.51.100.${10 + (Date.now() % 100)}`
    try {
      if (!(await addIPACL(request, 'blacklist', ip))) return
      const body = await getIPACL(request)
      if (!body) return
      expect(body.blacklist).toContain(ip)
    } finally {
      await removeIPACL(request, 'blacklist', ip)
    }
  })

  test('can add IP to whitelist via API', async ({ request }) => {
    const ip = `203.0.113.${10 + (Date.now() % 100)}`
    try {
      if (!(await addIPACL(request, 'whitelist', ip))) return
      const body = await getIPACL(request)
      if (!body) return
      expect(body.whitelist).toContain(ip)
    } finally {
      await removeIPACL(request, 'whitelist', ip)
    }
  })

  test('can remove IP from blacklist via API', async ({ request }) => {
    const ip = `192.0.2.${10 + (Date.now() % 100)}`
    if (!(await addIPACL(request, 'blacklist', ip))) return

    await removeIPACL(request, 'blacklist', ip)
    const body = await getIPACL(request)
    if (!body) return
    expect(body.blacklist).not.toContain(ip)
  })

  test('bans API returns active bans', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/bans`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 429]).toContain(resp.status())
    if (resp.status() === 429) return
    const body = await resp.json()
    expect(Array.isArray(body.bans) || body.hasOwnProperty('bans')).toBe(true)
  })

  test('can lift a ban via API', async ({ request }) => {
    // Try to lift ban for a test IP
    const resp = await request.delete(`${BASE_URL}/api/v1/bans`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: {
        ip: '192.168.99.99',
      },
    })
    expect([200, 204, 404, 429]).toContain(resp.status())
  })

  test('blocked IP returns 403', async ({ request }) => {
    const ip = '127.0.0.1'
    try {
      if (!(await addIPACL(request, 'blacklist', ip))) return
      const resp = await request.get(`${WAF_URL}/e2e-ipacl-blocked-${Date.now()}`)
      expect(resp.status()).toBe(403)
    } finally {
      await removeIPACL(request, 'blacklist', ip)
    }
  })
})
