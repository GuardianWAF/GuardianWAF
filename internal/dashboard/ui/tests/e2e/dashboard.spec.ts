import { expect, test } from '@playwright/test'

const apiKey = process.env.DASHBOARD_E2E_API_KEY || 'dashboard-e2e-secret'
const adminKey = process.env.DASHBOARD_E2E_ADMIN_KEY || 'dashboard-e2e-admin-secret'

test('login renders and opens the dashboard shell', async ({ page }) => {
  await page.goto('/login')

  await expect(page).toHaveTitle(/GuardianWAF/)
  await expect(page.getByRole('heading', { name: 'GuardianWAF' })).toBeVisible()

  await page.getByLabel('API Key').fill(apiKey)
  await page.getByRole('button', { name: 'Sign In' }).click()

  await expect(page).toHaveURL(/\/$/)
  await expect(page.getByRole('heading', { name: 'GuardianWAF Dashboard' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Routing' })).toBeVisible()
  await expect(page.getByRole('status', { name: /System health:/ })).toBeVisible()
})

test('dashboard health API is public and protected APIs require auth', async ({ request }) => {
  const health = await request.get('/api/v1/health')
  expect(health.ok()).toBeTruthy()
  await expect(health.json()).resolves.toMatchObject({ status: expect.any(String) })

  const stats = await request.get('/api/v1/stats')
  expect(stats.status()).toBe(401)
})

test('tenant admin UI requires the separate dashboard admin key', async ({ page, request }) => {
  const dashboardKeyResp = await request.get('/api/admin/tenants', {
    headers: {
      'X-API-Key': apiKey,
    },
  })
  expect(dashboardKeyResp.status()).toBe(401)

  const adminKeyResp = await request.get('/api/admin/tenants', {
    headers: {
      'X-API-Key': adminKey,
    },
  })
  expect(adminKeyResp.status()).toBe(200)

  await page.goto('/login')
  await page.getByLabel('API Key').fill(apiKey)
  await page.getByRole('button', { name: 'Sign In' }).click()
  await expect(page).toHaveURL(/\/$/)

  await page.goto('/tenants')
  await expect(page.getByLabel('dashboard.admin_key')).toBeVisible()

  await page.getByLabel('dashboard.admin_key').fill(adminKey)
  await page.getByRole('button', { name: 'Unlock' }).click()
  await expect(page.getByRole('button', { name: 'Clear admin key' })).toBeVisible()
})

const dashboardRoutes = [
  ['/', 'GuardianWAF Dashboard'],
  ['/routing', 'Routing Management'],
  ['/rules', 'Custom Rules'],
  ['/ssl', 'SSL / TLS'],
  ['/config', 'WAF Configuration'],
  ['/alerting', 'Alerting'],
  ['/ai', 'AI Threat Analysis'],
  ['/logs', 'Application Logs'],
  ['/analytics', 'Analytics'],
  ['/docker', 'Docker Discovery'],
  ['/compliance', 'Compliance'],
  ['/tenants', 'Tenant Management'],
  ['/clusters', 'Cluster Sync'],
] as const

test('every primary dashboard route renders without browser errors', async ({ page }) => {
  const browserErrors: string[] = []
  page.on('pageerror', (error) => browserErrors.push(`pageerror: ${error.message}`))
  page.on('console', (message) => {
    if (message.type() === 'error') browserErrors.push(`console: ${message.text()}`)
  })

  await page.goto('/login')
  await page.getByLabel('API Key').fill(apiKey)
  await page.getByRole('button', { name: 'Sign In' }).click()

  for (const [path, heading] of dashboardRoutes) {
    await page.goto(path)
    await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible()
    await expect(page.locator('body')).not.toContainText('Something went wrong')
  }

  expect(browserErrors).toEqual([])
})

test('mobile navigation is usable and pages do not overflow the viewport', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 })
  await page.goto('/login')
  await page.getByLabel('API Key').fill(apiKey)
  await page.getByRole('button', { name: 'Sign In' }).click()

  const openNavigation = page.getByRole('button', { name: 'Open navigation' })
  await expect(openNavigation).toBeVisible()
  await expect(page.locator('aside[aria-label="Primary navigation"]')).toHaveAttribute('aria-hidden', 'true')
  await openNavigation.click()
  const navigation = page.getByRole('complementary', { name: 'Primary navigation' })
  await expect(navigation).toBeVisible()
  await expect(navigation).toHaveAttribute('aria-hidden', 'false')
  await navigation.getByRole('link', { name: 'Routing' }).click()
  await expect(page).toHaveURL(/\/routing$/)
  await expect(page.getByRole('heading', { name: 'Routing Management' })).toBeVisible()
  await expect(navigation).not.toBeInViewport()

  const documentWidth = await page.evaluate(() => document.documentElement.scrollWidth)
  expect(documentWidth).toBeLessThanOrEqual(375)
})

test('unknown dashboard routes show a recoverable not-found page', async ({ page }) => {
  await page.goto('/login')
  await page.getByLabel('API Key').fill(apiKey)
  await page.getByRole('button', { name: 'Sign In' }).click()
  await page.goto('/this-page-does-not-exist')

  await expect(page.getByRole('heading', { name: 'Page not found' })).toBeVisible()
  await page.getByRole('link', { name: 'Back to dashboard' }).click()
  await expect(page).toHaveURL(/\/$/)
})
