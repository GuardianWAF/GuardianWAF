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
  const setCookie = loginResp.headers()['set-cookie'] || ''
  const cookies = setCookie.split(/\,\s*(?=gwaf_session=)/)
  const sessionCookie = cookies.find((c: string) => c.includes('gwaf_session'))
  return sessionCookie?.split(';')[0] || ''
}

test.describe('Docker Integration', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('docker containers API returns list', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/docker/containers`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('containers')
  })

  test('docker containers API returns discovered services', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/docker/services`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('services')
  })

  test('docker events API returns recent events', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/docker/events?limit=10`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('events')
  })

  test('docker page loads', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/docker`)

    await expect(page.getByRole('heading', { name: 'Docker Discovery' })).toBeVisible()
    await expect(page.locator('.docker-page')).toBeVisible()
  })

  test('docker page shows container list or empty state', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/docker`)
    await page.waitForTimeout(2000)

    await expect(page.getByRole('heading', { name: 'Discovered Services' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Containers' })).toBeVisible()
    await expect(page.locator('table, .empty-state').first()).toBeVisible()
  })
})
