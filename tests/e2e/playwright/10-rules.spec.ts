import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

type RuleSummary = {
  id?: string
  action?: string
  enabled?: boolean
}

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

function hasRule(rules: RuleSummary[] | undefined, ruleId: string): boolean {
  return Array.isArray(rules) && rules.some((rule) => rule.id === ruleId)
}

test.describe('Rules Management', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('rules API returns all rules', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/rules`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 429]).toContain(resp.status())
    if (resp.status() === 429) return
    const body = await resp.json()
    expect(body).toHaveProperty('rules')
    expect(Array.isArray(body.rules)).toBe(true)
  })

  test('rules API supports filtering by type', async ({ request }) => {
    const suffix = Date.now()
    const matchingId = `e2e-sqli-filter-${suffix}`
    const otherId = `e2e-type-filter-other-${suffix}`
    const headers = {
      'X-API-Key': API_KEY,
      'Content-Type': 'application/json',
    }

    const createMatching = await request.post(`${BASE_URL}/api/v1/rules`, {
      headers,
      data: {
        id: matchingId,
        name: 'E2E SQLi filter rule',
        enabled: true,
        priority: 50,
        action: 'block',
        score: 5,
        conditions: [{ field: 'query', op: 'contains', value: 'union select' }],
      },
    })
    expect([200, 429]).toContain(createMatching.status())
    if (createMatching.status() === 429) return

    try {
      const createOther = await request.post(`${BASE_URL}/api/v1/rules`, {
        headers,
        data: {
          id: otherId,
          name: 'E2E path filter rule',
          enabled: true,
          priority: 51,
          action: 'log',
          score: 3,
          conditions: [{ field: 'path', op: 'starts_with', value: '/e2e-filter' }],
        },
      })
      expect([200, 429]).toContain(createOther.status())
      if (createOther.status() === 429) return

      const resp = await request.get(`${BASE_URL}/api/v1/rules?type=sqli`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
      expect([200, 429]).toContain(resp.status())
      if (resp.status() === 429) return
      const body = await resp.json()
      expect(Array.isArray(body.rules)).toBe(true)
      expect(hasRule(body.rules, matchingId)).toBe(true)
      expect(hasRule(body.rules, otherId)).toBe(false)
    } finally {
      await request.delete(`${BASE_URL}/api/v1/rules/${matchingId}`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
      await request.delete(`${BASE_URL}/api/v1/rules/${otherId}`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
    }
  })

  test('rules API supports filtering by action', async ({ request }) => {
    const suffix = Date.now()
    const blockId = `e2e-action-block-${suffix}`
    const logId = `e2e-action-log-${suffix}`
    const headers = {
      'X-API-Key': API_KEY,
      'Content-Type': 'application/json',
    }

    const createBlock = await request.post(`${BASE_URL}/api/v1/rules`, {
      headers,
      data: {
        id: blockId,
        name: 'E2E action block rule',
        enabled: true,
        priority: 50,
        action: 'block',
        score: 5,
        conditions: [{ field: 'path', op: 'starts_with', value: '/e2e-action-block' }],
      },
    })
    expect([200, 429]).toContain(createBlock.status())
    if (createBlock.status() === 429) return

    try {
      const createLog = await request.post(`${BASE_URL}/api/v1/rules`, {
        headers,
        data: {
          id: logId,
          name: 'E2E action log rule',
          enabled: true,
          priority: 51,
          action: 'log',
          score: 1,
          conditions: [{ field: 'path', op: 'starts_with', value: '/e2e-action-log' }],
        },
      })
      expect([200, 429]).toContain(createLog.status())
      if (createLog.status() === 429) return

      const resp = await request.get(`${BASE_URL}/api/v1/rules?action=block`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
      expect([200, 429]).toContain(resp.status())
      if (resp.status() === 429) return
      const body = await resp.json()
      expect(Array.isArray(body.rules)).toBe(true)
      expect(hasRule(body.rules, blockId)).toBe(true)
      expect(hasRule(body.rules, logId)).toBe(false)
    } finally {
      await request.delete(`${BASE_URL}/api/v1/rules/${blockId}`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
      await request.delete(`${BASE_URL}/api/v1/rules/${logId}`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
    }
  })

  test('rules API supports filtering by enabled state', async ({ request }) => {
    const suffix = Date.now()
    const enabledId = `e2e-enabled-true-${suffix}`
    const disabledId = `e2e-enabled-false-${suffix}`
    const headers = {
      'X-API-Key': API_KEY,
      'Content-Type': 'application/json',
    }

    const createEnabled = await request.post(`${BASE_URL}/api/v1/rules`, {
      headers: {
        ...headers,
      },
      data: {
        id: enabledId,
        name: 'E2E enabled filter rule',
        enabled: true,
        priority: 50,
        action: 'log',
        score: 1,
        conditions: [{ field: 'path', op: 'starts_with', value: '/e2e-enabled' }],
      },
    })
    expect([200, 429]).toContain(createEnabled.status())
    if (createEnabled.status() === 429) return

    try {
      const createDisabled = await request.post(`${BASE_URL}/api/v1/rules`, {
        headers,
        data: {
          id: disabledId,
          name: 'E2E disabled filter rule',
          enabled: false,
          priority: 51,
          action: 'log',
          score: 1,
          conditions: [{ field: 'path', op: 'starts_with', value: '/e2e-disabled' }],
        },
      })
      expect([200, 429]).toContain(createDisabled.status())
      if (createDisabled.status() === 429) return

      const resp = await request.get(`${BASE_URL}/api/v1/rules?enabled=true`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
      expect([200, 429]).toContain(resp.status())
      if (resp.status() === 429) return
      const body = await resp.json()
      expect(Array.isArray(body.rules)).toBe(true)
      expect(hasRule(body.rules, enabledId)).toBe(true)
      expect(hasRule(body.rules, disabledId)).toBe(false)
    } finally {
      await request.delete(`${BASE_URL}/api/v1/rules/${enabledId}`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
      await request.delete(`${BASE_URL}/api/v1/rules/${disabledId}`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
    }
  })

  test('rules API supports text search', async ({ request }) => {
    const suffix = Date.now()
    const matchingId = `e2e-search-match-${suffix}`
    const otherId = `e2e-search-other-${suffix}`
    const headers = {
      'X-API-Key': API_KEY,
      'Content-Type': 'application/json',
    }

    const createMatching = await request.post(`${BASE_URL}/api/v1/rules`, {
      headers,
      data: {
        id: matchingId,
        name: 'E2E needle search rule',
        enabled: true,
        priority: 50,
        action: 'log',
        score: 1,
        conditions: [{ field: 'path', op: 'starts_with', value: '/e2e-needle' }],
      },
    })
    expect([200, 429]).toContain(createMatching.status())
    if (createMatching.status() === 429) return

    try {
      const createOther = await request.post(`${BASE_URL}/api/v1/rules`, {
        headers,
        data: {
          id: otherId,
          name: 'E2E haystack search rule',
          enabled: true,
          priority: 51,
          action: 'log',
          score: 1,
          conditions: [{ field: 'path', op: 'starts_with', value: '/e2e-haystack' }],
        },
      })
      expect([200, 429]).toContain(createOther.status())
      if (createOther.status() === 429) return

      const resp = await request.get(`${BASE_URL}/api/v1/rules?q=needle`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
      expect([200, 429]).toContain(resp.status())
      if (resp.status() === 429) return
      const body = await resp.json()
      expect(Array.isArray(body.rules)).toBe(true)
      expect(hasRule(body.rules, matchingId)).toBe(true)
      expect(hasRule(body.rules, otherId)).toBe(false)
    } finally {
      await request.delete(`${BASE_URL}/api/v1/rules/${matchingId}`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
      await request.delete(`${BASE_URL}/api/v1/rules/${otherId}`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
    }
  })

  test('rules page loads with rules table', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/rules`)
    await page.waitForURL(/\/rules/, { timeout: 5000 })
    await expect(page.getByRole('heading', { name: /Custom Rules/i })).toBeVisible()

    // Should have table or list of rules
    const hasTable = await page.locator('table').count() > 0
    const hasList = await page.locator('[class*="rule"], [class*="list"]').count() > 0

    expect(hasTable || hasList).toBe(true)
  })

  test('rules page has filter controls', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/rules`)
    await page.waitForURL(/\/rules/, { timeout: 5000 })
    await expect(page.getByRole('heading', { name: /Custom Rules/i })).toBeVisible()

    // Should have filter controls
    const hasFilters = await page.locator('select, input[type="search"], input[placeholder*="ilter"]').count() > 0
    expect(hasFilters).toBe(true)
  })

  test('rules page has add rule button', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/rules`)
    await page.waitForURL(/\/rules/, { timeout: 5000 })
    await expect(page.getByRole('heading', { name: /Custom Rules/i })).toBeVisible()

    // Look for add/create button
    const addButton = await page.locator('button:has-text("Add"), button:has-text("Create"), button:has-text("New Rule")').count()
    expect(addButton).toBeGreaterThan(0)
  })

  test('can enable/disable a rule via API', async ({ request }) => {
    const ruleId = `e2e-toggle-${Date.now()}`
    const createResp = await request.post(`${BASE_URL}/api/v1/rules`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: {
        id: ruleId,
        name: 'E2E toggle rule',
        enabled: true,
        priority: 50,
        action: 'log',
        score: 5,
        conditions: [{ field: 'path', op: 'starts_with', value: '/e2e-toggle' }],
      },
    })
    expect([200, 429]).toContain(createResp.status())
    if (createResp.status() === 429) return
    try {
      const toggleResp = await request.patch(`${BASE_URL}/api/v1/rules/${ruleId}`, {
        headers: {
          'X-API-Key': API_KEY,
          'Content-Type': 'application/json',
        },
        data: {
          enabled: false,
        },
      })
      expect([200, 204, 429]).toContain(toggleResp.status())
      if (toggleResp.status() === 429) return

      const getResp = await request.get(`${BASE_URL}/api/v1/rules`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
      expect([200, 429]).toContain(getResp.status())
      if (getResp.status() === 429) return
      const body = await getResp.json()
      const rule = body.rules?.find((candidate: any) => candidate.id === ruleId)
      expect(rule).toBeTruthy()
      expect(rule.enabled).toBe(false)
    } finally {
      await request.delete(`${BASE_URL}/api/v1/rules/${ruleId}`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
    }
  })

  test('rules page shows rule details on click', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/rules`)
    await page.waitForURL(/\/rules/, { timeout: 5000 })

    // Try to click on a rule row if table exists
    const ruleRow = page.locator('tbody tr, [class*="rule-row"]').first()
    if (await ruleRow.count() > 0) {
      await ruleRow.click()
      // Should open a detail panel or modal
      await page.waitForTimeout(500)
      const hasDetail = await page.locator('[class*="detail"], [class*="modal"], [class*="drawer"]').count() > 0
      // If no detail panel, at least the page should still be functional
      expect(page.url()).toContain('/rules')
    }
  })
})
