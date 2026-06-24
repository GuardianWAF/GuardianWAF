import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const WAF_URL = process.env.E2E_WAF_URL || 'http://localhost:8080'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

async function responseJSON(resp: any): Promise<any> {
  const text = await resp.text()
  return text ? JSON.parse(text) : {}
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

test.describe('AI Configuration', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('AI config API returns current settings', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/ai/config`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('enabled')
  })

  test('AI providers API returns a provider list or explicit catalog error', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/ai/providers`, {
      headers: { 'X-API-Key': API_KEY },
    })
    expect([200, 500]).toContain(resp.status())
    const body = await responseJSON(resp)
    if (resp.status() === 200) {
      expect(Array.isArray(body.providers)).toBe(true)
      expect(typeof body.count).toBe('number')
      expect(body.count).toBe(body.providers.length)
    } else {
      expect(String(body.error || '')).toMatch(/failed to fetch/i)
    }
  })

  test('AI config API accepts valid configuration', async ({ request }) => {
    const nextConfig = {
      provider_id: 'openai',
      provider_name: 'OpenAI',
      model_id: 'gpt-4o-mini',
      model_name: 'GPT-4o Mini',
      api_key: 'test-key',
      base_url: 'https://api.openai.com',
    }
    const resp = await request.put(`${BASE_URL}/api/v1/ai/config`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: nextConfig,
    })
    expect([200, 400]).toContain(resp.status())
    const body = await responseJSON(resp)
    if (resp.status() === 400) {
      expect(String(body.error || '')).toMatch(/AI analysis not enabled/i)
      return
    }
    expect(body.status).toBe('ok')

    const getResp = await request.get(`${BASE_URL}/api/v1/ai/config`, {
      headers: { 'X-API-Key': API_KEY },
    })
    expect(getResp.status()).toBe(200)
    const updated = await getResp.json()
    expect(updated.provider_id).toBe(nextConfig.provider_id)
    expect(updated.model_id).toBe(nextConfig.model_id)
    expect(updated.base_url).toBe(nextConfig.base_url)
    expect(updated.api_key_set).toBe(true)
    expect(updated.api_key_mask).toBe('****')
  })

  test('AI page loads with configuration form', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/ai`)
    await page.waitForURL(/\/ai/, { timeout: 5000 })
    await expect(page.getByRole('heading', { name: /AI Threat Analysis/i })).toBeVisible()

    // Should have form elements for AI configuration
    const hasInput = await page.locator('input').count() > 0

    expect(hasInput).toBe(true)
  })

  test('AI page shows provider selection', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/ai`)
    await page.waitForURL(/\/ai/, { timeout: 5000 })
    await expect(page.getByRole('heading', { name: /AI Threat Analysis/i })).toBeVisible()

    await expect(page.getByText(/Select AI Provider/i)).toBeVisible()

    const hasProviderSearch = await page.locator('input[placeholder*="Search providers"]').count() > 0
    expect(hasProviderSearch).toBe(true)
  })

  test('AI page shows analysis history section', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/ai`)
    await page.waitForURL(/\/ai/, { timeout: 5000 })

    // Should have some content area - table, list, or empty state
    const hasContent = await page.locator('table, ul, [data-testid*="history"], .empty-state').count() > 0
    expect(hasContent || (await page.content()).length > 1000).toBe(true)
  })

  test('AI analysis can be triggered manually', async ({ request }) => {
    // Send a request that would generate an event
    await request.get(`${WAF_URL}/e2e-ai-trigger-${Date.now()}?q=SELECT+*+FROM+users`).catch(() => {})

    // Trigger AI analysis
    const resp = await request.post(`${BASE_URL}/api/v1/ai/analyze?limit=20`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
    })
    expect([200, 400]).toContain(resp.status())
    const body = await responseJSON(resp)
    if (resp.status() === 400) {
      expect(String(body.error || '')).toMatch(/AI analysis not enabled/i)
      return
    }
    expect(body.message || body.id).toBeTruthy()
    if (body.id) {
      expect(typeof body.event_count).toBe('number')
      expect(Array.isArray(body.verdicts)).toBe(true)
    } else {
      expect(String(body.message)).toMatch(/no suspicious events/i)
    }
  })

  test('AI history endpoint returns a bounded list', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/ai/history?limit=5`, {
      headers: { 'X-API-Key': API_KEY },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(Array.isArray(body.history)).toBe(true)
    expect(body.history.length).toBeLessThanOrEqual(5)
    if ('count' in body) {
      expect(body.count).toBe(body.history.length)
    }
  })

  test('AI stats endpoint returns metrics', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/ai/stats`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('enabled')
    if (body.enabled) {
      expect(body).toHaveProperty('total_requests')
      expect(body).toHaveProperty('total_tokens_used')
    }
  })
})
