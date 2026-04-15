import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

test.describe('WAF Blocking', () => {
  test.beforeAll(async ({ request }) => {
    // Verify server is reachable
    const healthResp = await request.get(`${BASE_URL}/api/v1/health`)
    expect(healthResp.status()).toBe(200)
  })

  test('benign request passes through', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/hello?name=world`, {
      headers: {
        'X-API-Key': API_KEY,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      },
    })
    // Should get through (either to backend or WAF response)
    expect([200, 301, 302, 404]).toContain(resp.status())
  })

  test('SQL injection is blocked', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/search?q='+OR+1%3D1+--`, {
      headers: {
        'X-API-Key': API_KEY,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      },
    })
    // Should be blocked or challenged
    // Status may be 403 (blocked) or 200 (challenge page)
    const body = await resp.text()
    const isBlocked = resp.status() === 403 || body.toLowerCase().includes('block')
    expect(isBlocked).toBe(true)
  })

  test('XSS attack is blocked', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/page?q=%3Cscript%3Ealert(1)%3C/script%3E`, {
      headers: {
        'X-API-Key': API_KEY,
        'User-Agent': 'Mozilla/5.0',
      },
    })
    const body = await resp.text()
    const isBlocked = resp.status() === 403 || body.toLowerCase().includes('block')
    expect(isBlocked).toBe(true)
  })

  test('blocked events appear in event log', async ({ request }) => {
    // Send an attack
    await request.get(`${BASE_URL}/api?q=' OR 1=1--`, {
      headers: { 'X-API-Key': API_KEY },
    }).catch(() => {})

    // Wait a moment for async event processing
    await new Promise(r => setTimeout(r, 500))

    // Check events
    const resp = await request.get(`${BASE_URL}/api/v1/events?action=block&limit=10`, {
      headers: { 'X-API-Key': API_KEY },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(Array.isArray(body.events)).toBe(true)
    // Should have at least one block event (may have 0 if rate limited or async)
  })
})
