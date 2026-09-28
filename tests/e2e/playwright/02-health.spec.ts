import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const ADMIN_KEY = process.env.E2E_ADMIN_KEY || 'guardianwaf-full-e2e-admin-key'

test.describe('Health Endpoints', () => {
  test('health endpoint returns 200', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/health`)
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('status')
  })

  test('metrics endpoint returns prometheus format with admin key', async ({ request }) => {
    // /metrics is served only behind the dashboard admin key (4cbfbac).
    const resp = await request.get(`${BASE_URL}/metrics`, {
      headers: { 'X-API-Key': ADMIN_KEY },
    })
    expect(resp.status()).toBe(200)
    const text = await resp.text()
    expect(text).toContain('guardianwaf_')
  })

  test('metrics endpoint requires auth', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/metrics`)
    expect(resp.status()).toBe(401)
  })
})
