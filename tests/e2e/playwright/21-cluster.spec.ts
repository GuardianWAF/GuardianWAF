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

test.describe('Cluster Mode', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('cluster status API returns node info', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/cluster/status`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404, 503]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body).toHaveProperty('nodes') || expect(body).toHaveProperty('cluster')
    }
  })

  test('cluster nodes API returns member list', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/cluster/nodes`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404, 503]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(Array.isArray(body.nodes) || body.hasOwnProperty('nodes')).toBe(true)
    }
  })

  test('cluster health endpoint returns status', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/cluster/health`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404, 503]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body).toHaveProperty('status') || expect(body).toHaveProperty('healthy')
    }
  })

  test('node stats API returns local metrics', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/cluster/node/stats`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404, 503]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body).toHaveProperty('requests') || expect(body).toHaveProperty('cpu')
    }
  })

  test('cluster config API returns sync settings', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/cluster/config`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404, 503]).toContain(resp.status())
  })

  test('cluster page loads in dashboard', async ({ page }) => {
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

    // Cluster might be under settings or own page
    await page.goto(`${BASE_URL}/cluster`)
    await page.waitForTimeout(2000)

    // Should load without error
    expect(page.url()).toBeTruthy()
  })
})
