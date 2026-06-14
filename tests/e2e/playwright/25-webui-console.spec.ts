import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

const routes = [
  '/',
  '/logs',
  '/config',
  '/docker',
  '/rules',
  '/routing',
  '/alerting',
  '/ai',
  '/ssl',
  '/analytics',
  '/compliance',
  '/tenants',
  '/tenants/e2e-missing-tenant',
  '/tenants/e2e-missing-tenant/analytics',
  '/clusters',
  '/clusters/e2e-missing-cluster',
]

async function getSessionCookie(request: any): Promise<string> {
  const loginResp = await request.post(`${BASE_URL}/login`, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Origin': BASE_URL,
    },
    form: { key: API_KEY },
  })
  expect([200, 302]).toContain(loginResp.status())
  const setCookie = loginResp.headers()['set-cookie'] || ''
  const cookies = setCookie.split(/,\s*(?=gwaf_session=)/)
  const sessionCookie = cookies.find((c: string) => c.includes('gwaf_session'))
  return sessionCookie?.split(';')[0] || ''
}

test.describe('Web UI Runtime Health', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
    expect(sessionCookie).toContain('gwaf_session=')
  })

  for (const route of routes) {
    test(`${route} renders without browser runtime errors`, async ({ page }) => {
      const errors: string[] = []

      page.on('console', (message) => {
        if (message.type() === 'error') {
          errors.push(message.text())
        }
      })
      page.on('pageerror', (error) => {
        errors.push(error.message)
      })

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

      await page.goto(`${BASE_URL}${route}`, { waitUntil: 'domcontentloaded' })
      await expect(page.locator('main')).toBeVisible()
      await page.waitForTimeout(750)

      expect(errors).toEqual([])
    })
  }
})
