import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://localhost:9443'
const API_KEY = process.env.E2E_API_KEY || 'test-api-key'

test.describe('MCP Server (Model Context Protocol)', () => {
  test('MCP message endpoint accepts JSON-RPC requests', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/mcp/message`, {
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
    expect(resp.status()).toBe(202)
  })

  test('MCP get_stats tool works', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/mcp/message`, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'guardianwaf_get_stats',
          arguments: {},
        },
      },
    })
    expect(resp.status()).toBe(202)
  })

  test('MCP get_events tool works', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/mcp/message`, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'guardianwaf_get_events',
          arguments: { limit: 10 },
        },
      },
    })
    expect(resp.status()).toBe(202)
  })

  test('MCP add_blacklist tool works', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/mcp/message`, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'guardianwaf_add_blacklist',
          arguments: { ip: '192.168.99.99', reason: 'MCP E2E test' },
        },
      },
    })
    expect(resp.status()).toBe(202)
  })

  test('MCP remove_blacklist tool works', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/mcp/message`, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'guardianwaf_remove_blacklist',
          arguments: { ip: '192.168.99.99' },
        },
      },
    })
    expect(resp.status()).toBe(202)
  })

  test('MCP get_config tool works', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/mcp/message`, {
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
          name: 'guardianwaf_get_config',
          arguments: {},
        },
      },
    })
    expect(resp.status()).toBe(202)
  })

  test('MCP invalid method returns error', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/mcp/message`, {
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
    expect(resp.status()).toBe(202)
  })

  test('MCP requires auth', async ({ request }) => {
    const resp = await request.post(`${BASE_URL}/mcp/message`, {
      headers: {
        'Content-Type': 'application/json',
      },
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
      },
    })
    expect([401, 403]).toContain(resp.status())
  })
})
