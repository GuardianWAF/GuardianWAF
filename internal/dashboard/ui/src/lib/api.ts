const BASE = ''

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(body.error || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  // Stats
  getStats: () => request<Stats>('/api/v1/stats'),

  // Events
  getEvents: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<EventsResponse>('/api/v1/events' + qs)
  },

  // Upstreams health
  getUpstreams: () => request<UpstreamStatus[]>('/api/v1/upstreams'),

  // Config
  getConfig: () => request<WafConfig>('/api/v1/config'),
  updateConfig: (patch: Partial<WafConfig>) =>
    request<ApiResult>('/api/v1/config', { method: 'PUT', body: JSON.stringify(patch) }),

  // Routing
  getRouting: () => request<RoutingConfig>('/api/v1/routing'),
  updateRouting: (data: RoutingConfig) =>
    request<ApiResult>('/api/v1/routing', { method: 'PUT', body: JSON.stringify(data) }),

  // IP ACL
  getIPACL: () => request<IpAclData>('/api/v1/ipacl'),
  addIP: (list: string, ip: string) =>
    request<ApiResult>('/api/v1/ipacl', { method: 'POST', body: JSON.stringify({ list, ip }) }),
  removeIP: (list: string, ip: string) =>
    request<ApiResult>('/api/v1/ipacl', { method: 'DELETE', body: JSON.stringify({ list, ip }) }),
}

// --- Types ---

export interface Stats {
  total_requests: number
  blocked_requests: number
  challenged_requests: number
  logged_requests: number
  passed_requests: number
  avg_latency_us: number
}

export interface WafEvent {
  id: string
  timestamp: string
  request_id: string
  client_ip: string
  method: string
  path: string
  query: string
  action: string
  score: number
  findings: Finding[]
  duration_ns: number
  status_code: number
  user_agent: string
  browser: string
  browser_version: string
  os: string
  device_type: string
  is_bot: boolean
  content_type?: string
  referer?: string
  host?: string
}

export interface Finding {
  detector: string
  category: string
  severity: string
  score: number
  description: string
  matched_value?: string
  location: string
  confidence: number
}

export interface EventsResponse {
  events: WafEvent[]
  total: number
  limit: number
  offset: number
}

export interface UpstreamStatus {
  name: string
  strategy: string
  targets: TargetStatus[]
  healthy_count: number
  total_count: number
}

export interface TargetStatus {
  url: string
  healthy: boolean
  circuit_state: string
  active_conns: number
  weight: number
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export interface WafConfig {
  mode: string
  waf: Record<string, any>
}

export interface RoutingConfig {
  upstreams: UpstreamConfig[]
  virtual_hosts: VirtualHostConfig[]
  routes: RouteConfig[]
}

export interface UpstreamConfig {
  name: string
  load_balancer: string
  targets: { url: string; weight: number }[]
  health_check: { enabled: boolean; interval: string; timeout: string; path: string }
}

export interface VirtualHostConfig {
  domains: string[]
  tls: { cert_file: string; key_file: string }
  routes: RouteConfig[]
}

export interface RouteConfig {
  path: string
  upstream: string
  strip_prefix: boolean
}

export interface IpAclData {
  whitelist: string[]
  blacklist: string[]
}

export interface ApiResult {
  status: string
  message?: string
  error?: string
}
