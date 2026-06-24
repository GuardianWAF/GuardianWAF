import { test, expect, Page } from '@playwright/test'

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

async function readSSEStart(page: Page, path: string, headers: Record<string, string> = {}) {
  await page.goto(`${BASE_URL}/login`)
  return page.evaluate(async ({ path, headers }) => {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 1000)
    try {
      const resp = await fetch(path, {
        headers: {
          Accept: 'text/event-stream',
          ...headers,
        },
        credentials: 'same-origin',
        signal: controller.signal,
      })
      const reader = resp.body?.getReader()
      const chunk = reader ? await reader.read() : null
      await reader?.cancel()
      return {
        status: resp.status,
        contentType: resp.headers.get('content-type') || '',
        firstChunk: chunk?.value ? new TextDecoder().decode(chunk.value) : '',
      }
    } finally {
      clearTimeout(timeout)
    }
  }, { path, headers })
}

test.describe('Realtime Event Stream', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('primary SSE endpoint streams events with API key auth', async ({ page }) => {
    const result = await readSSEStart(page, '/api/v1/sse', { 'X-API-Key': API_KEY })
    expect(result.status).toBe(200)
    expect(result.contentType).toContain('text/event-stream')
    expect(result.firstChunk).toContain('connected')
  })

  test('SSE compatibility alias streams events with API key auth', async ({ page }) => {
    const result = await readSSEStart(page, '/api/v1/events/stream', { 'X-API-Key': API_KEY })
    expect(result.status).toBe(200)
    expect(result.contentType).toContain('text/event-stream')
    expect(result.firstChunk).toContain('connected')
  })

  test('SSE endpoint requires auth', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/events/stream`, {
      headers: {
        'Accept': 'text/event-stream',
      },
    })
    expect(resp.status()).toBe(401)
    const body = await resp.json()
    expect(body.error).toBe('unauthorized')
  })

  test('SSE endpoint accepts authenticated session cookie', async ({ page }) => {
    expect(sessionCookie).toContain('gwaf_session=')
    await page.context().addCookies([
      {
        name: 'gwaf_session',
        value: sessionCookie.split('=')[1] || '',
        domain: new URL(BASE_URL).hostname,
        path: '/',
        httpOnly: true,
        secure: false,
      },
    ])

    const result = await readSSEStart(page, '/api/v1/sse')
    expect(result.status).toBe(200)
    expect(result.contentType).toContain('text/event-stream')
    expect(result.firstChunk).toContain('connected')
  })
})
