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
  // Generic request methods
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body: JSON.stringify(body) }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PUT', body: JSON.stringify(body) }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),

  // Stats
  getStats: () => request<Stats>('/api/v1/stats'),

  // Events
  getEvents: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<EventsResponse>('/api/v1/events' + qs)
  },

  // Upstreams health
  getUpstreams: () => request<UpstreamStatus[]>('/api/v1/upstreams'),

  // SSL Certificates
  getSSL: () => request<any>('/api/v1/ssl'),

  // Config
  getConfig: () => request<WafConfig>('/api/v1/config'),
  updateConfig: (patch: Partial<WafConfig>) =>
    request<ApiResult>('/api/v1/config', { method: 'PUT', body: JSON.stringify(patch) }),

  // Routing
  getRouting: () => request<RoutingConfig>('/api/v1/routing'),
  updateRouting: (data: RoutingConfig) =>
    request<ApiResult>('/api/v1/routing', { method: 'PUT', body: JSON.stringify(data) }),

  // Logs
  getLogs: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : ''
    return request<LogsResponse>('/api/v1/logs' + qs)
  },

  // IP ACL
  getIPACL: () => request<IpAclData>('/api/v1/ipacl'),
  addIP: (list: string, ip: string) =>
    request<ApiResult>('/api/v1/ipacl', { method: 'POST', body: JSON.stringify({ list, ip }) }),
  removeIP: (list: string, ip: string) =>
    request<ApiResult>('/api/v1/ipacl', { method: 'DELETE', body: JSON.stringify({ list, ip }) }),

  // Temp Bans
  getBans: () => request<BansResponse>('/api/v1/bans'),
  addBan: (ip: string, duration: string, reason?: string) =>
    request<ApiResult>('/api/v1/bans', { method: 'POST', body: JSON.stringify({ ip, duration, reason }) }),
  removeBan: (ip: string) =>
    request<ApiResult>('/api/v1/bans', { method: 'DELETE', body: JSON.stringify({ ip }) }),

  // Custom Rules
  getRules: () => request<RulesResponse>('/api/v1/rules'),
  addRule: (rule: CustomRule) =>
    request<ApiResult>('/api/v1/rules', { method: 'POST', body: JSON.stringify(rule) }),
  updateRule: (id: string, rule: CustomRule) =>
    request<ApiResult>('/api/v1/rules/' + id, { method: 'PUT', body: JSON.stringify(rule) }),
  deleteRule: (id: string) =>
    request<ApiResult>('/api/v1/rules/' + id, { method: 'DELETE' }),

  // GeoIP
  geoipLookup: (ip: string) =>
    request<GeoIPResult>('/api/v1/geoip/lookup?ip=' + encodeURIComponent(ip)),

  // Alerting
  getAlertingStatus: () => request<AlertingStatusResponse>('/api/v1/alerting/status'),
  getWebhooks: () => request<WebhooksResponse>('/api/v1/alerting/webhooks'),
  addWebhook: (webhook: WebhookConfig) =>
    request<ApiResult>('/api/v1/alerting/webhooks', { method: 'POST', body: JSON.stringify(webhook) }),
  deleteWebhook: (name: string) =>
    request<ApiResult>('/api/v1/alerting/webhooks/' + encodeURIComponent(name), { method: 'DELETE' }),
  getEmails: () => request<EmailsResponse>('/api/v1/alerting/emails'),
  addEmail: (email: EmailConfig) =>
    request<ApiResult>('/api/v1/alerting/emails', { method: 'POST', body: JSON.stringify(email) }),
  deleteEmail: (name: string) =>
    request<ApiResult>('/api/v1/alerting/emails/' + encodeURIComponent(name), { method: 'DELETE' }),
  testAlert: (target: string) =>
    request<ApiResult>('/api/v1/alerting/test', { method: 'POST', body: JSON.stringify({ target }) }),

  // Tenants
  getTenants: () => request<Tenant[]>('/api/v1/tenants'),
  getTenant: (id: string) => request<Tenant>('/api/v1/tenants/' + id),
  createTenant: (tenant: CreateTenantRequest) =>
    request<Tenant>('/api/v1/tenants', { method: 'POST', body: JSON.stringify(tenant) }),
  updateTenant: (id: string, tenant: UpdateTenantRequest) =>
    request<Tenant>('/api/v1/tenants/' + id, { method: 'PUT', body: JSON.stringify(tenant) }),
  deleteTenant: (id: string) =>
    request<void>('/api/v1/tenants/' + id, { method: 'DELETE' }),
  getTenantUsage: (id: string) => request<TenantUsage>('/api/v1/tenants/' + id + '/usage'),
  getAllUsage: () => request<TenantUsage[]>('/api/v1/tenants/usage'),
  regenerateApiKey: (id: string) =>
    request<{ api_key: string }>('/api/v1/tenants/' + id + '/apikey', { method: 'POST' }),

  // Cluster Sync
  getClusters: () => request<Cluster[]>('/api/clusters'),
  getCluster: (id: string) => request<Cluster>('/api/clusters/' + id),
  createCluster: (cluster: CreateClusterRequest) =>
    request<Cluster>('/api/clusters', { method: 'POST', body: JSON.stringify(cluster) }),
  deleteCluster: (id: string) =>
    request<void>('/api/clusters/' + id, { method: 'DELETE' }),
  joinCluster: (id: string, node: ClusterNode) =>
    request<ClusterNode>('/api/clusters/' + id + '?action=join', { method: 'POST', body: JSON.stringify(node) }),
  leaveCluster: (id: string, nodeId: string) =>
    request<void>('/api/clusters/' + id + '?action=leave&node_id=' + encodeURIComponent(nodeId), { method: 'POST' }),
  getNodes: () => request<ClusterNode[]>('/api/nodes'),
  getSyncStats: () => request<SyncStats>('/api/sync/stats'),
  getSyncStatus: () => request<SyncStatusResponse>('/api/sync/status'),
}

// --- Types ---

export interface Stats {
  total_requests: number
  blocked_requests: number
  challenged_requests: number
  logged_requests: number
  passed_requests: number
  avg_latency_us: number
  alerting?: AlertingStats
}

export interface AlertingStats {
  sent: number
  failed: number
  webhook_count: number
  email_count: number
  email?: {
    sent: number
    failed: number
  }
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
  // TLS information
  tls_version?: string
  tls_cipher?: string
  ja3_hash?: string
  ja4_fingerprint?: string
  sni?: string
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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  tls: Record<string, any>
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
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

export interface LogEntry {
  time: string
  level: string
  message: string
}

export interface LogsResponse {
  logs: LogEntry[]
  total: number
}

export interface ApiResult {
  status: string
  message?: string
  error?: string
}

export interface BanEntry {
  ip: string
  reason: string
  expires_at: string
  count: number
}

export interface BansResponse {
  bans: BanEntry[]
}

export interface CustomRule {
  id: string
  name: string
  enabled: boolean
  priority: number
  conditions: RuleCondition[]
  action: string
  score: number
}

export interface RuleCondition {
  field: string
  op: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  value: any
}

export interface RulesResponse {
  rules: CustomRule[]
}

export interface GeoIPResult {
  ip: string
  country: string
  name: string
}

// Alerting Types
export interface AlertingStatusResponse {
  enabled: boolean
  webhook_count: number
  email_count: number
  sent?: number
  failed?: number
  webhooks: WebhookConfig[]
  emails: EmailConfig[]
}

export interface WebhooksResponse {
  webhooks: WebhookConfig[]
}

export interface EmailsResponse {
  emails: EmailConfig[]
}

export interface WebhookConfig {
  name: string
  url: string
  type: 'slack' | 'discord' | 'pagerduty' | 'generic'
  events: string[]
  min_score: number
  cooldown: string
  headers?: Record<string, string>
}

export interface EmailConfig {
  name: string
  smtp_host: string
  smtp_port: number
  username?: string
  password?: string
  from: string
  to: string[]
  use_tls: boolean
  events: string[]
  min_score: number
  cooldown: string
  subject?: string
  template?: string
}

// Tenant Types
export interface Tenant {
  id: string
  name: string
  description?: string
  active: boolean
  domains: string[]
  created_at: string
  updated_at: string
  plan?: string
  quota?: ResourceQuota
}

export interface ResourceQuota {
  max_requests_per_minute: number
  max_requests_per_hour: number
  max_bandwidth_mbps: number
  max_rules: number
  max_rate_limit_rules: number
  max_ip_acls: number
  max_domains?: number
}

export interface CreateTenantRequest {
  name: string
  description?: string
  domains: string[]
  quota?: ResourceQuota
}

export interface UpdateTenantRequest {
  name?: string
  description?: string
  active?: boolean
  domains?: string[]
  quota?: ResourceQuota
}

export interface TenantUsage {
  tenant_id: string
  name: string
  active: boolean
  requests_per_minute: number
  total_requests: number
  blocked_requests: number
  bytes_transferred: number
  bandwidth_mbps: number
  quota_percentage: number
  quota_status: 'ok' | 'warning' | 'exceeded' | 'unlimited'
  last_request_at?: string
}

// Cluster Sync Types
export interface Cluster {
  id: string
  name: string
  description?: string
  nodes: string[]
  sync_scope: 'tenants' | 'rules' | 'config' | 'all'
  created_at: string
}

export interface ClusterNode {
  id: string
  name: string
  address: string
  healthy?: boolean
  version?: string
  last_seen?: string
  is_local?: boolean
}

export interface CreateClusterRequest {
  id?: string
  name: string
  description?: string
  sync_scope?: string
}

export interface SyncStats {
  total_events_sent: number
  total_events_received: number
  total_conflicts: number
  total_resolved: number
  active_connections: number
  last_conflict_at?: string
}

export interface SyncStatusResponse {
  local_node: string
  nodes: ReplicationStatus[]
}

export interface ReplicationStatus {
  node_id: string
  last_replication: string
  pending_events: number
  failed_attempts: number
  lag_ms: number
  sync_status: Record<string, string>
}
