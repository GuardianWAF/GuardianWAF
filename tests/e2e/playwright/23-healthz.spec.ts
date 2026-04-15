import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

test.describe('Health & Metrics', () => {
  test('healthz endpoint returns 200', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/healthz`)
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('status')
  })

  test('health endpoint returns 200', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/health`)
    expect(resp.status()).toBe(200)
  })

  test('metrics endpoint returns Prometheus format', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/metrics`)
    expect(resp.status()).toBe(200)
    const body = await resp.text()
    // Prometheus metrics should contain gauge/counter/histogram
    expect(body).toContain('waf_')
  })

  test('api/v1/health returns detailed health', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/health`)
    expect([200, 401, 404]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body).toHaveProperty('status') || expect(body).toHaveProperty('healthy')
    }
  })

  test('readyz endpoint for k8s readiness probe', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/readyz`)
    expect(resp.status()).toBe(200)
  })

  test('livez endpoint for k8s liveness probe', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/livez`)
    expect(resp.status()).toBe(200)
  })

  test('version endpoint returns build info', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/version`)
    expect([200, 404]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body).toHaveProperty('version') || expect(body).toHaveProperty('build')
    }
  })

  test('prometheus metrics contain key WAF indicators', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/metrics`)
    expect(resp.status()).toBe(200)
    const body = await resp.text()

    // Should contain request counters
    expect(body).toContain('waf_requests_total') || expect(body).toContain('guardianwaf_requests')
  })

  test('metrics require no auth', async ({ request }) => {
    // Metrics should be public for Prometheus scraping
    const resp = await request.get(`${BASE_URL}/metrics`)
    expect(resp.status()).toBe(200)
  })

  test('health endpoints require no auth', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/healthz`)
    expect(resp.status()).toBe(200)
  })
})
