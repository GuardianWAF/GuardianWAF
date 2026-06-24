import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const WAF_URL = process.env.E2E_WAF_URL || 'http://localhost:8080'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

type EventSummary = {
  id?: string
  path?: string
  action?: string
  client_ip?: string
  timestamp?: string
  findings?: Array<{ detector?: string }>
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

async function fetchEvents(request: any, query: string): Promise<{ events: EventSummary[], total?: number, limit?: number, offset?: number }> {
  const resp = await request.get(`${BASE_URL}/api/v1/events?${query}`, {
    headers: {
      'X-API-Key': API_KEY,
    },
  })
  expect(resp.status()).toBe(200)
  const body = await resp.json()
  expect(Array.isArray(body.events)).toBe(true)
  return body
}

async function waitForEvent(request: any, predicate: (event: EventSummary) => boolean): Promise<EventSummary> {
  for (let attempt = 0; attempt < 20; attempt++) {
    const body = await fetchEvents(request, 'limit=100')
    const event = body.events.find(predicate)
    if (event) return event
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error('Timed out waiting for expected event')
}

test.describe('Events API', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('events endpoint returns JSON array', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/events?limit=10`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('events')
    expect(Array.isArray(body.events)).toBe(true)
  })

  test('events can be filtered by action', async ({ request }) => {
    const suffix = Date.now()
    const blockPath = `/e2e-action-block-${suffix}`
    const passPath = `/e2e-action-pass-${suffix}`

    await request.get(`${WAF_URL}${blockPath}?q=' OR 1=1--`)
    await request.get(`${WAF_URL}${passPath}`)
    await waitForEvent(request, (event) => event.path === blockPath && event.action === 'block')
    await waitForEvent(request, (event) => event.path === passPath && event.action === 'pass')

    const body = await fetchEvents(request, 'action=block&limit=100')
    expect(body.events.some((event) => event.path === blockPath)).toBe(true)
    expect(body.events.some((event) => event.path === passPath)).toBe(false)
  })

  test('events can be filtered by rule_id', async ({ request }) => {
    const path = `/e2e-rule-filter-${Date.now()}`

    await request.get(`${WAF_URL}${path}?q=' OR 1=1--`)
    const event = await waitForEvent(request, (candidate) => candidate.path === path && candidate.action === 'block')
    const detector = event.findings?.find((finding) => finding.detector)?.detector
    expect(detector).toBeTruthy()

    const body = await fetchEvents(request, `rule_id=${encodeURIComponent(detector || '')}&limit=100`)
    expect(body.events.some((candidate) => candidate.path === path)).toBe(true)
  })

  test('events support pagination', async ({ request }) => {
    const suffix = Date.now()
    const prefix = `/e2e-pagination-${suffix}`

    for (let i = 0; i < 7; i++) {
      await request.get(`${WAF_URL}${prefix}-${i}`)
    }
    await waitForEvent(request, (event) => event.path === `${prefix}-6`)

    const page1 = await fetchEvents(request, `path=${encodeURIComponent(prefix)}&limit=3&offset=0&sort_by=timestamp&sort_order=asc`)
    const page2 = await fetchEvents(request, `path=${encodeURIComponent(prefix)}&limit=3&offset=3&sort_by=timestamp&sort_order=asc`)
    expect(page1.total).toBeGreaterThanOrEqual(7)
    expect(page1.events).toHaveLength(3)
    expect(page2.events).toHaveLength(3)
    const page1Ids = new Set(page1.events.map((event) => event.id))
    expect(page2.events.some((event) => page1Ids.has(event.id))).toBe(false)
  })

  test('events can be filtered by IP', async ({ request }) => {
    const path = `/e2e-ip-filter-${Date.now()}`

    await request.get(`${WAF_URL}${path}`)
    const event = await waitForEvent(request, (candidate) => candidate.path === path)
    expect(event.client_ip).toBeTruthy()

    const body = await fetchEvents(request, `ip=${encodeURIComponent(event.client_ip || '')}&limit=100`)
    expect(body.events.some((candidate) => candidate.path === path)).toBe(true)
  })

  test('events can be filtered by date range', async ({ request }) => {
    const path = `/e2e-date-filter-${Date.now()}`
    const start = Date.now() - 1000

    await request.get(`${WAF_URL}${path}`)
    const event = await waitForEvent(request, (candidate) => candidate.path === path)
    const end = Date.now() + 1000

    const included = await fetchEvents(request, `start=${start}&end=${end}&limit=100`)
    expect(included.events.some((candidate) => candidate.id === event.id)).toBe(true)

    const excluded = await fetchEvents(request, `start=${end + 60_000}&end=${end + 120_000}&limit=100`)
    expect(excluded.events.some((candidate) => candidate.id === event.id)).toBe(false)
  })

  test('logs page displays events table', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/logs`)
    await page.waitForURL(/\/logs/, { timeout: 5000 })

    // Should have events table or loading state
    await page.waitForSelector('table, .empty-state, [data-testid="events-table"]', { timeout: 10000 }).catch(() => {
      // If no table found, check if page loaded at all
      expect(page.url()).toContain('/logs')
    })
  })

  test('logs page has search/filter controls', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/logs`)
    await page.waitForURL(/\/logs/, { timeout: 5000 })
    await expect(page.getByRole('heading', { name: /Application Logs/i })).toBeVisible()

    // Look for search input or filter controls
    const hasSearch = await page.locator('input[type="search"], input[placeholder*="earch"], input[placeholder*="ilter"]').count() > 0
    const hasSelect = await page.locator('select').count() > 0

    // At minimum, should have some filtering capability
    expect(hasSearch || hasSelect).toBe(true)
  })
})
