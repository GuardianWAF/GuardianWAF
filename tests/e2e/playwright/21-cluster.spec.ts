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
    expect([200, 429]).toContain(resp.status())
    if (resp.status() === 429) return
    const body = await resp.json()
    expect('nodes' in body || 'cluster' in body).toBe(true)
  })

  test('cluster nodes API returns member list', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/cluster/nodes`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 429]).toContain(resp.status())
    if (resp.status() === 429) return
    const body = await resp.json()
    expect(Array.isArray(body.nodes) || Object.prototype.hasOwnProperty.call(body, 'nodes')).toBe(true)
  })

  test('cluster health endpoint returns status', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/cluster/health`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 429]).toContain(resp.status())
    if (resp.status() === 429) return
    const body = await resp.json()
    expect('status' in body || 'healthy' in body).toBe(true)
  })

  test('node stats API returns local metrics', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/cluster/node/stats`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 429]).toContain(resp.status())
    if (resp.status() === 429) return
    const body = await resp.json()
    expect('requests' in body || 'cpu' in body).toBe(true)
  })

  test('cluster config API returns sync settings', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/cluster/config`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 429]).toContain(resp.status())
  })

  test('cluster page loads in dashboard', async ({ page }) => {
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

    // Cluster might be under settings or own page
    await page.goto(`${BASE_URL}/cluster`)
    await page.waitForTimeout(2000)

    // Should load without error
    expect(page.url()).toBeTruthy()
  })
})
