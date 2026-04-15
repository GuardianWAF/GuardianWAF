import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

test.describe('Config API', () => {
  let cookies: string[] = []

  test.beforeAll(async ({ request }) => {
    // Login to get session cookie
    const loginResp = await request.post(`${BASE_URL}/login`, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': BASE_URL,
      },
      form: {
        key: API_KEY,
      },
    })
    cookies = loginResp.headers()['set-cookie'] || []
  })

  test('returns full config', async ({ request }) => {
    // Extract session cookie
    const sessionCookie = cookies.find(c => c.includes('session'))
    const cookieValue = sessionCookie?.split(';')[0] || ''

    const resp = await request.get(`${BASE_URL}/api/v1/config`, {
      headers: { 'Cookie': cookieValue },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('mode')
    expect(body).toHaveProperty('tls')
    expect(body).toHaveProperty('waf')
  })

  test('IP ACL endpoints work', async ({ request }) => {
    const sessionCookie = cookies.find(c => c.includes('session'))
    const cookieValue = sessionCookie?.split(';')[0] || ''

    const resp = await request.get(`${BASE_URL}/api/v1/ipacl`, {
      headers: { 'Cookie': cookieValue },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('whitelist')
    expect(body).toHaveProperty('blacklist')
    expect(Array.isArray(body.whitelist)).toBe(true)
    expect(Array.isArray(body.blacklist)).toBe(true)
  })

  test('AI config returns status', async ({ request }) => {
    const sessionCookie = cookies.find(c => c.includes('session'))
    const cookieValue = sessionCookie?.split(';')[0] || ''

    const resp = await request.get(`${BASE_URL}/api/v1/ai/config`, {
      headers: { 'Cookie': cookieValue },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('enabled')
  })
})
