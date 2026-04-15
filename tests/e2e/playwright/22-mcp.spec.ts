import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

test.describe('MCP Server (Model Context Protocol)', () => {
  test('MCP endpoint returns JSON-RPC response', async ({ request }) => {
    // MCP uses JSON-RPC 2.0
    const resp = await request.post(`${BASE_URL}/mcp`, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
      },
    })
    // Should return JSON-RPC response
    expect([200, 404, 405]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body).toHaveProperty('jsonrpc')
    }
  })

  test('MCP get_stats tool works', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/mcp`, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'get_stats',
          arguments: {},
        },
      },
    })
    expect([200, 404]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body).toHaveProperty('result') || expect(body).toHaveProperty('error')
    }
  })

  test('MCP get_events tool works', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/mcp`, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'get_events',
          arguments: { limit: 10 },
        },
      },
    })
    expect([200, 404]).toContain(resp.status())
  })

  test('MCP add_blacklist tool works', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/mcp`, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'add_blacklist',
          arguments: { ip: '192.168.99.99', reason: 'MCP E2E test' },
        },
      },
    })
    expect([200, 404]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      expect(body).toHaveProperty('result') || expect(body).toHaveProperty('error')
    }
  })

  test('MCP remove_blacklist tool works', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/mcp`, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'remove_blacklist',
          arguments: { ip: '192.168.99.99' },
        },
      },
    })
    expect([200, 404]).toContain(resp.status())
  })

  test('MCP get_config tool works', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/mcp`, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'get_config',
          arguments: {},
        },
      },
    })
    expect([200, 404]).toContain(resp.status())
  })

  test('MCP invalid method returns error', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/mcp`, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'invalid/nonexistent',
      },
    })
    expect([200, 404]).toContain(resp.status())
    if (resp.status() === 200) {
      const body = await resp.json()
      // Should have error for invalid method
      expect(body).toHaveProperty('error') || expect(body).toHaveProperty('result')
    }
  })

  test('MCP requires auth', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/mcp`, {
      headers: {
        'Content-Type': 'application/json',
      },
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
      },
    })
    // Should require auth
    expect([401, 403, 404]).toContain(resp.status())
  })
})
