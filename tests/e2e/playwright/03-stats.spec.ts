import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

test.describe('Stats API', () => {
  test('returns stats with valid API key', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/stats`, {
      headers: { 'X-API-Key': API_KEY },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('total_requests')
    expect(body).toHaveProperty('blocked_requests')
    expect(body).toHaveProperty('passed_requests')
  })

  test('returns 401 without API key', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/stats`)
    expect(resp.status()).toBe(401)
  })
})

test.describe('Events API', () => {
  test('returns events with valid API key', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/events?limit=10`, {
      headers: { 'X-API-Key': API_KEY },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('events')
    expect(body).toHaveProperty('total')
    expect(Array.isArray(body.events)).toBe(true)
  })

  test('supports pagination', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/events?limit=5&offset=0`, {
      headers: { 'X-API-Key': API_KEY },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body.limit).toBe(5)
    expect(body.offset).toBe(0)
  })

  test('filters by action', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/events?action=block`, {
      headers: { 'X-API-Key': API_KEY },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    for (const ev of body.events) {
      expect(ev.action).toBe('block')
    }
  })
})
