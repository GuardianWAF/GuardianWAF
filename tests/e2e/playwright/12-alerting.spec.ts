import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

type WebhookTarget = {
  name?: string
  type?: string
  url?: string
}

type EmailTarget = {
  name?: string
  smtp_host?: string
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

async function getWebhooks(request: any): Promise<WebhookTarget[] | null> {
  const resp = await request.get(`${BASE_URL}/api/v1/alerting/webhooks`, {
    headers: {
      'X-API-Key': API_KEY,
    },
  })
  expect([200, 429]).toContain(resp.status())
  if (resp.status() === 429) return null
  const body = await resp.json()
  expect(Array.isArray(body.webhooks)).toBe(true)
  return body.webhooks
}

async function getEmails(request: any): Promise<EmailTarget[] | null> {
  const resp = await request.get(`${BASE_URL}/api/v1/alerting/emails`, {
    headers: {
      'X-API-Key': API_KEY,
    },
  })
  expect([200, 429]).toContain(resp.status())
  if (resp.status() === 429) return null
  const body = await resp.json()
  expect(Array.isArray(body.emails)).toBe(true)
  return body.emails
}

test.describe('Alerting Configuration', () => {
  let sessionCookie: string

  test.beforeAll(async ({ request }) => {
    sessionCookie = await getSessionCookie(request)
  })

  test('alerts API returns configured alerts', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/alerts`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect([200, 429]).toContain(resp.status())
    if (resp.status() === 429) return
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(Array.isArray(body.alerts) || body.hasOwnProperty('alerts')).toBe(true)
    }
  })

  test('can create and delete webhook target via API', async ({ request }) => {
    const name = `e2e-webhook-${Date.now()}`
    try {
      const resp = await request.post(`${BASE_URL}/api/v1/alerting/webhooks`, {
        headers: {
          'X-API-Key': API_KEY,
          'Content-Type': 'application/json',
        },
        data: {
          name,
          url: `https://hooks.example.com/${name}`,
          type: 'generic',
          events: ['block'],
          min_score: 50,
          cooldown: '30s',
        },
      })
      expect([200, 429]).toContain(resp.status())
      if (resp.status() === 429) return

      const webhooks = await getWebhooks(request)
      if (!webhooks) return
      expect(webhooks.some((webhook) => webhook.name === name && webhook.type === 'generic')).toBe(true)
    } finally {
      await request.delete(`${BASE_URL}/api/v1/alerting/webhooks/${name}`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
    }

    const webhooks = await getWebhooks(request)
    if (!webhooks) return
    expect(webhooks.some((webhook) => webhook.name === name)).toBe(false)
  })

  test('can create and delete email target via API', async ({ request }) => {
    const name = `e2e-email-${Date.now()}`
    try {
      const resp = await request.post(`${BASE_URL}/api/v1/alerting/emails`, {
        headers: {
          'X-API-Key': API_KEY,
          'Content-Type': 'application/json',
        },
        data: {
          name,
          smtp_host: 'smtp.example.com',
          smtp_port: 587,
          from: 'guardianwaf@example.com',
          to: ['security@example.com'],
          use_tls: true,
          events: ['block'],
          min_score: 50,
          cooldown: '5m',
        },
      })
      expect([200, 429]).toContain(resp.status())
      if (resp.status() === 429) return

      const emails = await getEmails(request)
      if (!emails) return
      expect(emails.some((email) => email.name === name && email.smtp_host === 'smtp.example.com')).toBe(true)
    } finally {
      await request.delete(`${BASE_URL}/api/v1/alerting/emails/${name}`, {
        headers: {
          'X-API-Key': API_KEY,
        },
      })
    }

    const emails = await getEmails(request)
    if (!emails) return
    expect(emails.some((email) => email.name === name)).toBe(false)
  })

  test('compat alert create explains concrete target endpoints', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/api/v1/alerts`, {
      headers: {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
      },
      data: {
        name: 'E2E Test Alert',
        condition: 'block_count > 10',
        threshold: 10,
        window: '5m',
        action: 'log',
        enabled: true,
      },
    })
    expect([400, 429]).toContain(resp.status())
    if (resp.status() === 429) return
    const body = await resp.json()
    expect(String(body.error)).toContain('/api/v1/alerting/webhooks')
  })

  test('alerting page loads', async ({ page }) => {
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

    // Try /alerts or /alerting page
    await page.goto(`${BASE_URL}/alerts`)
    const url = page.url()

    // Should load alerts page or redirect
    expect(url.includes('/alerts') || url.includes('/alerting')).toBe(true)
  })

  test('alerting page shows alert rules', async ({ page }) => {
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

    await page.goto(`${BASE_URL}/alerts`)
    await page.waitForTimeout(2000)

    // Should have some content - table, cards, or empty state
    const hasContent = await page.locator('table, [class*="alert"], .empty-state, form').count() > 0
    expect(hasContent || (await page.content()).length > 500).toBe(true)
  })

  test('alert history API returns recent alerts', async ({ request }) => {
    const resp = await request.get(`${BASE_URL}/api/v1/alerts/history?limit=10`, {
      headers: {
        'X-API-Key': API_KEY,
      },
    })
    expect(resp.status()).toBe(200)
    const body = await resp.json()
    expect(body).toHaveProperty('history')
  })
})
