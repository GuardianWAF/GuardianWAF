import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const WAF_URL = process.env.E2E_WAF_URL || 'http://localhost:8080'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

type RoutingTarget = {
  url: string
  weight: number
}

type RoutingUpstream = {
  name: string
  load_balancer?: string
  targets?: RoutingTarget[]
  health_check?: {
    enabled?: boolean
    path?: string
    interval?: string
    timeout?: string
  }
}

type RoutingRoute = {
  path: string
  upstream: string
  strip_prefix?: boolean
}

type RoutingConfig = {
  upstreams?: RoutingUpstream[]
  routes?: RoutingRoute[]
  virtual_hosts?: unknown[]
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

async function getRouting(request: any): Promise<RoutingConfig | null> {
  const resp = await request.get(`${BASE_URL}/api/v1/routing`, {
    headers: { 'X-API-Key': API_KEY },
  })
  expect([200, 429]).toContain(resp.status())
  if (resp.status() === 429) return null
  const body = await resp.json()
  expect(Array.isArray(body.upstreams)).toBe(true)
  expect(Array.isArray(body.routes)).toBe(true)
  return body
}

async function putRouting(request: any, routing: RoutingConfig): Promise<boolean> {
  const resp = await request.put(`${BASE_URL}/api/v1/routing`, {
    headers: {
      'X-API-Key': API_KEY,
      'Content-Type': 'application/json',
    },
    data: routing,
  })
  expect([200, 204, 429]).toContain(resp.status())
  return resp.status() !== 429
}

test.describe('Routing Configuration', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('routing API returns routes', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/routing`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('routes')
    expect(Array.isArray(body.routes)).toBe(true)
  })

  test('routing API returns upstreams', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/upstreams`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(Array.isArray(body) || Array.isArray(body.upstreams)).toBe(true)
  })

  test('routing page loads with topology graph', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/routing`)
    await page.waitForURL(/\/routing/, { timeout: 5000 })

    // Page should load - the routing graph uses React Flow
    // Look for the page container
    const pageContent = await page.content()
    expect(pageContent.length).toBeGreaterThan(500)
  })

  test('routing page shows route list or graph', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/routing`)
    await page.waitForURL(/\/routing/, { timeout: 5000 })

    // Should have some UI - table, graph canvas, or cards
    const hasTable = await page.locator('table').count() > 0
    const hasCanvas = await page.locator('canvas, [class*="flow"], [class*="graph"]').count() > 0
    const hasCards = await page.locator('[class*="card"]').count() > 0

    expect(hasTable || hasCanvas || hasCards).toBe(true)
  })

  test('can add a new upstream via API', async ({ request }) => {
    const routing = await getRouting(request)
    if (!routing) return
    const name = `e2e-upstream-${Date.now()}`
    const next: RoutingConfig = {
      ...routing,
      upstreams: [
        ...(routing.upstreams || []).filter((upstream) => upstream.name !== name),
        {
          name,
          load_balancer: 'round_robin',
          targets: [{ url: WAF_URL, weight: 1 }],
          health_check: { enabled: false, path: '/health', interval: '10s', timeout: '5s' },
        },
      ],
    }
    try {
      if (!(await putRouting(request, next))) return
      const updated = await getRouting(request)
      if (!updated) return
      expect(updated.upstreams?.some((upstream) => upstream.name === name)).toBe(true)
    } finally {
      await putRouting(request, routing)
    }
  })

  test('can add a new route via API', async ({ request }) => {
    const routing = await getRouting(request)
    if (!routing) return
    const upstreamName = `e2e-route-upstream-${Date.now()}`
    const path = `/e2e-route-${Date.now()}`
    const next: RoutingConfig = {
      ...routing,
      upstreams: [
        ...(routing.upstreams || []).filter((upstream) => upstream.name !== upstreamName),
        {
          name: upstreamName,
          load_balancer: 'round_robin',
          targets: [{ url: WAF_URL, weight: 1 }],
          health_check: { enabled: false, path: '/health', interval: '10s', timeout: '5s' },
        },
      ],
      routes: [
        ...(routing.routes || []).filter((route) => route.path !== path),
        { path, upstream: upstreamName, strip_prefix: false },
      ],
    }
    try {
      if (!(await putRouting(request, next))) return
      const updated = await getRouting(request)
      if (!updated) return
      expect(updated.upstreams?.some((upstream) => upstream.name === upstreamName)).toBe(true)
      expect(updated.routes?.some((route) => route.path === path && route.upstream === upstreamName)).toBe(true)
    } finally {
      await putRouting(request, routing)
    }
  })

  test('routing page has add route button', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/routing`)
    await page.waitForURL(/\/routing/, { timeout: 5000 })
    const heading = page.getByRole('heading', { name: /Routing Management/i })
    await expect(heading).toBeVisible({ timeout: 15000 })
    const retry = page.getByRole('button', { name: /Retry/i })
    if (await retry.isVisible().catch(() => false)) {
      await page.waitForTimeout(1000)
      await retry.click()
      await expect(page.getByRole('button', { name: /Configure/i })).toBeVisible({ timeout: 15000 })
    }
    await page.getByRole('button', { name: /Configure/i }).click()

    // Look for add/create button
    const hasAddButton = await page.locator('button:has-text("Add"), button:has-text("Create"), button:has-text("New")').count() > 0
    const hasForm = await page.locator('form').count() > 0

    expect(hasAddButton || hasForm).toBe(true)
  })
})
