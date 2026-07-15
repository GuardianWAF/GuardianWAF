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
const primaryMobileRoutes = routes.filter((route) => !route.includes('e2e-missing'))
const responsiveViewports = [
  { name: 'narrow mobile', width: 320, height: 568 },
  { name: 'mobile', width: 375, height: 812 },
  { name: 'tablet', width: 768, height: 1024 },
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

async function addSessionCookie(page: any, sessionCookie: string): Promise<void> {
  const baseURL = new URL(BASE_URL)
  await page.context().addCookies([
    {
      name: 'gwaf_session',
      value: sessionCookie.split('=')[1] || '',
      domain: baseURL.hostname,
      path: '/',
      httpOnly: true,
      secure: baseURL.protocol === 'https:',
    },
  ])
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

      await addSessionCookie(page, sessionCookie)

      await page.goto(`${BASE_URL}${route}`, { waitUntil: 'domcontentloaded' })
      await expect(page.locator('main')).toBeVisible()
      await page.waitForTimeout(750)

      expect(errors).toEqual([])
    })
  }

  test('responsive navigation and primary routes stay usable without viewport overflow', async ({ page }) => {
    const navigationErrors: string[] = []
    page.on('console', (message) => {
      if (message.type() === 'error') navigationErrors.push(message.text())
    })
    page.on('pageerror', (error) => navigationErrors.push(error.message))

    await page.setViewportSize({ width: 375, height: 812 })
    await addSessionCookie(page, sessionCookie)
    await page.goto(BASE_URL, { waitUntil: 'domcontentloaded' })

    const openNavigation = page.getByRole('button', { name: 'Open navigation' })
    await expect(openNavigation).toBeVisible()
    const hiddenNavigation = page.locator('aside[aria-label="Primary navigation"]')
    await expect(hiddenNavigation).toHaveAttribute('aria-hidden', 'true')
    await openNavigation.click()
    const navigation = page.getByRole('complementary', { name: 'Primary navigation' })
    await expect(navigation).toBeVisible()
    await expect(navigation).toHaveAttribute('aria-hidden', 'false')
    await navigation.getByRole('link', { name: 'Routing' }).click()
    await expect(page).toHaveURL(/\/routing$/)
    await expect(navigation).not.toBeInViewport()
    expect(navigationErrors).toEqual([])

    for (const viewport of responsiveViewports) {
      for (const route of primaryMobileRoutes) {
        const routePage = await page.context().newPage()
        const routeErrors: string[] = []
        routePage.on('console', (message) => {
          if (message.type() === 'error') routeErrors.push(message.text())
        })
        routePage.on('pageerror', (error) => routeErrors.push(error.message))

        await routePage.setViewportSize({ width: viewport.width, height: viewport.height })
        await routePage.goto(`${BASE_URL}${route}`, { waitUntil: 'domcontentloaded' })
        await expect(routePage.locator('main')).toBeVisible()
        const dimensions = await routePage.evaluate(() => ({
          viewport: document.documentElement.clientWidth,
          document: document.documentElement.scrollWidth,
        }))
        expect(
          dimensions.document,
          `${route} overflowed the ${viewport.name} viewport`,
        ).toBeLessThanOrEqual(dimensions.viewport)
        await routePage.waitForTimeout(250)
        expect(routeErrors, `${route} emitted browser runtime errors at ${viewport.name}`).toEqual([])
        await routePage.close()
      }
    }
  })
})
