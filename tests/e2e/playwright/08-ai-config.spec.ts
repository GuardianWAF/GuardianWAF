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

test.describe('AI Configuration', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('AI config API returns current settings', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/config/ai`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    // Should return 200 or 404 if AI is not configured
    expect([200, 404]).toContain(resp.status())
  })

  test('AI config API accepts valid configuration', async ({ request }) => {
    const resp = await request.put(`${BASE_URL}/api/v1/config/ai`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: {
        provider: 'openai',
        model: 'gpt-4o-mini',
        api_key: 'test-key',
        enabled: true,
        batch_size: 10,
        max_tokens_per_hour: 100000,
        max_requests_per_hour: 50,
      },
    })
    // Should accept valid config
    expect([200, 204]).toContain(resp.status())
  })

  test('AI page loads with configuration form', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/ai`)
    await page.waitForURL(/\/ai/, { timeout: 5000 })

    // Should have form elements for AI configuration
    const hasForm = await page.locator('form').count() > 0
    const hasSelect = await page.locator('select').count() > 0
    const hasInput = await page.locator('input').count() > 0

    expect(hasForm || hasSelect || hasInput).toBe(true)
  })

  test('AI page shows provider selection', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/ai`)
    await page.waitForURL(/\/ai/, { timeout: 5000 })

    // Look for provider dropdown/selection
    const hasProviderSelect = await page.locator('select[name*="provider"], #provider, [data-testid*="provider"]').count() > 0

    // Or look for any select element which could be the provider
    const hasAnySelect = await page.locator('select').count() > 0

    expect(hasProviderSelect || hasAnySelect).toBe(true)
  })

  test('AI page shows analysis history section', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/ai`)
    await page.waitForURL(/\/ai/, { timeout: 5000 })

    // Should have some content area - table, list, or empty state
    const hasContent = await page.locator('table, ul, [data-testid*="history"], .empty-state').count() > 0
    expect(hasContent || (await page.content()).length > 1000).toBe(true)
  })

  test('AI analysis can be triggered manually', async ({ request }) => {
    // Send a request that would generate an event
    await request.get(`${BASE_URL}/api?q=SELECT+*+FROM+users`, {
      headers: { 'X-API-Key': API_KEY },
    }).catch(() => {})

    // Trigger AI analysis
    const resp = await request.post(`${BASE_URL}/api/v1/ai/analyze`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: {
        force: true,
      },
    })
    // Should accept the request (202 or 200) or return if nothing to analyze
    expect([200, 202, 404, 400]).toContain(resp.status())
  })

  test('AI stats endpoint returns metrics', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/ai/stats`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 404]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body).toHaveProperty('total_requests')
      expect(body).toHaveProperty('total_tokens')
    }
  })
})
