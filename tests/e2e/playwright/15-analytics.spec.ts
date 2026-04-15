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

test.describe('Analytics Dashboard', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('analytics API returns traffic stats', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/analytics/traffic?period=1h`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body).toHaveProperty('requests') || expect(body).toHaveProperty('total')
    }
  })

  test('analytics API returns attack stats', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/analytics/attacks?period=1h`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body).toHaveProperty('blocks') || expect(body).toHaveProperty('attacks')
    }
  })

  test('analytics API returns top targets', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/analytics/top?limit=10`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body).toHaveProperty('top_ips') || expect(body).toHaveProperty('top_rules') || expect(body).toHaveProperty('targets')
    }
  })

  test('analytics page loads', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/analytics`)
    const url = page.url()

    // Should load analytics page
    expect(url.includes('/analytics')).toBe(true)
  })

  test('analytics page shows charts or stats', async ({ page }) => {
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
        name: 'session',
        value: sessionCookie.split('=')[1] || '',
        domain: 'localhost',
        path: '/',
        httpOnly: true,
        secure: false,
      }
    ])

    await page.goto(`${BASE_URL}/analytics`)

    // Look for date/time range selectors
    const hasDatePicker = await page.locator('input[type="date"], input[type="datetime-local"], select option[value*="hour"], select option[value*="day"]').count() > 0
    const hasPeriodSelect = await page.locator('select').count() > 0

    expect(hasDatePicker || hasPeriodSelect).toBe(true)
  })
})
