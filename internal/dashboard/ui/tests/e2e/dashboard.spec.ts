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
