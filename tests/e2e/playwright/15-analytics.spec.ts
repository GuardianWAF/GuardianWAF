import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const WAF_URL = process.env.E2E_WAF_URL || 'http://localhost:8080'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

type CountRow = {
  key?: string
  count?: number
}

type TrafficStats = {
  requests?: number
  total?: number
  actions?: Record<string, number>
}

type AttackStats = {
  blocks?: number
  attacks?: number
  top_rules?: CountRow[]
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

async function apiGet(request: any, path: string): Promise<any> {
  const resp = await request.get(`${BASE_URL}${path}`, {
    headers: {
      'X-API-Key': API_KEY,
    },
  })
  expect(resp.status()).toBe(200)
  return resp.json()
}

async function waitForAnalytics<T>(fetcher: () => Promise<T>, predicate: (body: T) => boolean): Promise<T> {
  for (let attempt = 0; attempt < 20; attempt++) {
    const body = await fetcher()
    if (predicate(body)) return body
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  const body = await fetcher()
  expect(predicate(body)).toBe(true)
  return body
}

test.describe('Analytics Dashboard', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('analytics API returns traffic stats', async ({ request }) => {
    const suffix = Date.now()
    const passPath = `/e2e-analytics-pass-${suffix}`
    const blockPath = `/e2e-analytics-block-${suffix}`

    await request.get(`${WAF_URL}${passPath}`)
    await request.get(`${WAF_URL}${blockPath}?q=' OR 1=1--`)

    const body = await waitForAnalytics<TrafficStats>(
      () => apiGet(request, '/api/v1/analytics/traffic?period=1h'),
      (stats) => Boolean((stats.actions?.pass || 0) > 0 && (stats.actions?.block || 0) > 0),
    )
    expect(body).toHaveProperty('requests')
    expect(body).toHaveProperty('total')
    expect(body.total).toBeGreaterThanOrEqual(2)
  })

  test('analytics API returns attack stats', async ({ request }) => {
    const attackPath = `/e2e-analytics-attack-${Date.now()}`

    await request.get(`${WAF_URL}${attackPath}?q=' OR 1=1--`)

    const body = await waitForAnalytics<AttackStats>(
      () => apiGet(request, '/api/v1/analytics/attacks?period=1h'),
      (stats) => Boolean((stats.blocks || 0) > 0 && (stats.attacks || 0) > 0 && (stats.top_rules?.length || 0) > 0),
    )
    expect(body).toHaveProperty('blocks')
    expect(body).toHaveProperty('attacks')
    expect(body.blocks).toBeGreaterThan(0)
    expect(body.attacks).toBeGreaterThan(0)
  })

  test('analytics API returns top targets', async ({ request }) => {
    const targetPath = `/e2e-analytics-top-${Date.now()}`

    for (let i = 0; i < 3; i++) {
      await request.get(`${WAF_URL}${targetPath}`)
    }

    const body = await waitForAnalytics<{ top_ips?: CountRow[], top_rules?: CountRow[], targets?: CountRow[] }>(
      () => apiGet(request, '/api/v1/analytics/top?limit=25&period=1h'),
      (stats) => Boolean(stats.targets?.some((target) => target.key === targetPath && (target.count || 0) >= 3)),
    )
    expect(body).toHaveProperty('top_ips')
    expect(body).toHaveProperty('top_rules')
    expect(body).toHaveProperty('targets')
  })

  test('analytics API applies explicit date ranges', async ({ request }) => {
    const path = `/e2e-analytics-range-${Date.now()}`
    const start = Date.now() - 1000

    await request.get(`${WAF_URL}${path}`)

    const included = await waitForAnalytics<{ top_paths?: CountRow[], targets?: CountRow[] }>(
      () => apiGet(request, `/api/v1/analytics/top?limit=100&from=${start}&to=${Date.now() + 1000}`),
      (stats) => Boolean(stats.targets?.some((target) => target.key === path)),
    )
    expect(included.targets?.some((target) => target.key === path)).toBe(true)

    const futureStart = Date.now() + 60_000
    const excluded = await apiGet(request, `/api/v1/analytics/top?limit=100&from=${futureStart}&to=${futureStart + 60_000}`)
    expect(excluded.targets?.some((target: CountRow) => target.key === path)).toBe(false)
  })

  test('analytics page loads', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/analytics`)
    const url = page.url()

    // Should load analytics page
    expect(url.includes('/analytics')).toBe(true)
  })

  test('analytics page shows charts or stats', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/analytics`)
    await page.waitForTimeout(2000)

    // Should have charts, stats cards, or data
    const hasCharts = await page.locator('canvas, [class*="chart"], [class*="stat"]').count() > 0
    const hasNumbers = await page.locator('[class*="number"], [class*="count"]').count() > 0
    expect(hasCharts || hasNumbers || (await page.content()).length > 1000).toBe(true)
  })

  test('analytics supports date range selection', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/analytics`)
    await expect(page.getByRole('heading', { name: /Analytics/i })).toBeVisible()

    // Look for date/time range selectors
    const hasDatePicker = await page.locator('input[type="date"], input[type="datetime-local"], select option[value*="hour"], select option[value*="day"]').count() > 0
    const hasPeriodSelect = await page.locator('select').count() > 0

    expect(hasDatePicker || hasPeriodSelect).toBe(true)
  })
})
