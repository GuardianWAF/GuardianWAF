import { useState, useCallback } from 'react'
import { usePollingLoad } from '@/hooks/use-mount-load'
import { useParams, useNavigate } from 'react-router'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { useToast } from '@/components/ui/toast'
import { AdminKeyGate } from '@/components/admin-key-gate'
import { api, AdminTenantDetail, TenantUsage as TenantUsageType } from '@/lib/api'
import {
  ArrowLeft,
  RefreshCw,
  Download,
  Activity,
  Shield,
  Globe,
  BarChart3,
  AlertTriangle,
  Calendar,
  Clock,
  Zap,
  Ban
} from 'lucide-react'

// Helper to safely access tenant quota with defaults
const getQuota = (tenant: AdminTenantDetail) => ({
  max_requests_per_minute: tenant.quota?.max_requests_per_minute ?? 0,
  max_requests_per_hour: tenant.quota?.max_requests_per_hour ?? 0,
  max_bandwidth_mbps: tenant.quota?.max_bandwidth_mbps ?? 0,
  max_rules: tenant.quota?.max_rules ?? 0,
  max_rate_limit_rules: tenant.quota?.max_rate_limit_rules ?? 0,
  max_ip_acls: tenant.quota?.max_ip_acls ?? 0,
  max_domains: tenant.quota?.max_domains ?? 0,
})

interface UsageHistory {
  date: string
  requests: number
  blocked: number
  bandwidth_gb: number
}

function tenantUsageFromSummary(tenant: AdminTenantDetail): TenantUsageType {
  const maxRPM = tenant.quota?.max_requests_per_minute ?? 0
  const requestsPerMinute = 0
  const quotaPercentage = maxRPM > 0 ? (requestsPerMinute / maxRPM) * 100 : 0
  return {
    tenant_id: tenant.id,
    name: tenant.name,
    active: tenant.status === 'active',
    requests_per_minute: requestsPerMinute,
    total_requests: tenant.usage?.requests_this_month ?? 0,
    blocked_requests: tenant.usage?.blocked_requests ?? 0,
    bytes_transferred: 0,
    bandwidth_mbps: 0,
    quota_percentage: quotaPercentage,
    quota_status: maxRPM > 0 ? 'ok' : 'unlimited'
  }
}

export default function TenantAnalyticsPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [loading, setLoading] = useState(true)
  const [tenant, setTenant] = useState<AdminTenantDetail | null>(null)
  const [usage, setUsage] = useState<TenantUsageType | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d'>('24h')
  const [adminReady, setAdminReady] = useState(api.hasAdminKey())
  const { toast } = useToast()

  const loadData = useCallback(async () => {
    if (!id) return
    if (!adminReady) {
      setLoading(false)
      return
    }
    try {
      const list = await api.adminGetTenants()
      if (list.enabled === false || !list.tenants.some((tenant) => tenant.id === id)) {
        setTenant(null)
        setUsage(null)
        return
      }
      const tenantData = await api.adminGetTenant(id)
      let usageData: TenantUsageType
      try {
        usageData = await api.adminGetUsage(id)
      } catch {
        usageData = tenantUsageFromSummary(tenantData)
      }
      setTenant(tenantData)
      setUsage(usageData)
    } catch (error: unknown) {
      if (error instanceof Error && error.message.toLowerCase().includes('unauthorized')) {
        api.clearAdminKey()
        setAdminReady(false)
      }
      toast({
        title: 'Error',
        description: 'Failed to load tenant analytics',
        variant: 'destructive'
      })
    } finally {
      setLoading(false)
    }
  }, [id, adminReady, toast])

  const refreshData = async () => {
    setRefreshing(true)
    await loadData()
    setRefreshing(false)
    toast({ title: 'Refreshed', description: 'Analytics data updated' })
  }

  const exportData = () => {
    if (!tenant || !usage) return

    const data = {
      tenant: {
        id: tenant.id,
        name: tenant.name,
        description: tenant.description,
        domains: tenant.domains,
        created_at: tenant.created_at
      },
      usage: {
        total_requests: usage.total_requests,
        blocked_requests: usage.blocked_requests,
        bytes_transferred: usage.bytes_transferred,
        bandwidth_mbps: usage.bandwidth_mbps,
        requests_per_minute: usage.requests_per_minute,
        quota_percentage: usage.quota_percentage,
        quota_status: usage.quota_status
      },
      exported_at: new Date().toISOString()
    }

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `tenant-${tenant.id}-analytics-${new Date().toISOString().split('T')[0]}.json`
    a.click()
    URL.revokeObjectURL(url)

    toast({ title: 'Exported', description: 'Analytics data downloaded' })
  }

  usePollingLoad(loadData, 30000) // Refresh every 30s

  if (!adminReady) {
    return (
      <AdminKeyGate locked={!adminReady} onLocked={() => setAdminReady(false)} onUnlocked={() => {
        setAdminReady(true)
        setLoading(true)
      }}>
        <></>
      </AdminKeyGate>
    )
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg">Loading analytics...</div>
      </div>
    )
  }

  if (!tenant || !usage) {
    return (
      <div className="max-w-4xl mx-auto text-center py-8">
        <h1 className="text-2xl font-bold mb-4">Tenant Not Found</h1>
        <Button onClick={() => navigate('/tenants')}>
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Tenants
        </Button>
      </div>
    )
  }

  const blockedPercentage = usage.total_requests > 0
    ? (usage.blocked_requests / usage.total_requests * 100).toFixed(1)
    : '0'

  const getStatusBg = (status: string) => {
    switch (status) {
      case 'ok': return 'bg-green-50 border-green-200 dark:bg-green-900/20 dark:border-green-800'
      case 'warning': return 'bg-yellow-50 border-yellow-200 dark:bg-yellow-900/20 dark:border-yellow-800'
      case 'exceeded': return 'bg-red-50 border-red-200 dark:bg-red-900/20 dark:border-red-800'
      default: return 'bg-muted/10 border-border'
    }
  }

  const history: UsageHistory[] = []
  const totalRequestsInRange = history.length > 0
    ? history.reduce((sum, h) => sum + h.requests, 0)
    : usage.total_requests
  const totalBlockedInRange = history.length > 0
    ? history.reduce((sum, h) => sum + h.blocked, 0)
    : usage.blocked_requests
  const totalBandwidthInRange = history.length > 0
    ? history.reduce((sum, h) => sum + h.bandwidth_gb, 0)
    : usage.bytes_transferred / (1024 * 1024 * 1024)
  const quota = getQuota(tenant)
  const bandwidthPercent = quota.max_bandwidth_mbps > 0
    ? Math.min((usage.bandwidth_mbps / quota.max_bandwidth_mbps) * 100, 100)
    : 0

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-4">
          <Button variant="ghost" onClick={() => navigate('/tenants')}>
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back
          </Button>
          <div>
            <h1 className="text-3xl font-bold">{tenant.name}</h1>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <span>Usage Analytics</span>
              <Badge variant={tenant.status === 'active' ? 'default' : 'secondary'}>
                {tenant.status}
              </Badge>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center bg-muted/15 rounded-lg p-1">
            {(['24h', '7d', '30d'] as const).map((range) => (
              <button
                key={range}
                onClick={() => setTimeRange(range)}
                className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
                  timeRange === range
                    ? 'bg-card shadow-sm'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                {range === '24h' ? '24 Hours' : range === '7d' ? '7 Days' : '30 Days'}
              </button>
            ))}
          </div>
          <Button variant="outline" onClick={refreshData} disabled={refreshing}>
            <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button variant="outline" onClick={exportData}>
            <Download className="w-4 h-4 mr-2" />
            Export
          </Button>
          <Button onClick={() => navigate(`/tenants/${id}`)}>
            Edit Tenant
          </Button>
        </div>
      </div>

      {/* Status Banner */}
      <div className={`p-4 rounded-lg border ${getStatusBg(usage.quota_status)}`}>
        <div className="flex items-center gap-3">
          {usage.quota_status === 'exceeded' ? (
            <AlertTriangle className="w-5 h-5 text-red-600" />
          ) : usage.quota_status === 'warning' ? (
            <AlertTriangle className="w-5 h-5 text-yellow-600" />
          ) : (
            <Activity className="w-5 h-5 text-green-600" />
          )}
          <div className="flex-1">
            <div className="font-medium">
              {usage.quota_status === 'exceeded'
                ? 'Quota Exceeded - Action Required'
                : usage.quota_status === 'warning'
                ? 'Approaching Quota Limit'
                : 'All Systems Operational'}
            </div>
            <div className="text-sm text-muted-foreground">
              {usage.quota_status === 'exceeded'
                ? 'This tenant has exceeded its rate limit quota. Requests over the limit are rejected with 429; raise the quota if the traffic is legitimate.'
                : usage.quota_status === 'warning'
                ? `${usage.quota_percentage.toFixed(1)}% of quota used. Monitor closely.`
                : 'Usage is within normal parameters.'}
            </div>
          </div>
          {usage.quota_status !== 'ok' && (
            <Button size="sm" variant="default" onClick={() => navigate(`/tenants/${tenant.id}`)}>
              Edit Quota
            </Button>
          )}
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <Activity className="w-4 h-4" />
              Requests/min
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{usage.requests_per_minute.toLocaleString()}</div>
            <div className="text-sm text-muted-foreground">
              Limit: {quota.max_requests_per_minute > 0 ? quota.max_requests_per_minute.toLocaleString() : '∞'}
            </div>
            <div className="mt-2 h-1.5 bg-border rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${usage.quota_percentage > 90 ? 'bg-red-500' : usage.quota_percentage > 70 ? 'bg-yellow-500' : 'bg-green-500'}`}
                style={{ width: `${Math.min(usage.quota_percentage, 100)}%` }}
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <BarChart3 className="w-4 h-4" />
              Total Requests ({timeRange})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{totalRequestsInRange.toLocaleString()}</div>
            <div className="text-sm text-muted-foreground">
              {blockedPercentage}% blocked
            </div>
            <div className="mt-2 text-sm text-muted-foreground">
              {usage.total_requests.toLocaleString()} all-time total
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Threats Blocked
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-600">{totalBlockedInRange.toLocaleString()}</div>
            <div className="text-sm text-muted-foreground">
              {usage.blocked_requests.toLocaleString()} all-time
            </div>
            <div className="mt-2 text-sm text-muted-foreground">
              {((totalBlockedInRange / (totalRequestsInRange || 1)) * 100).toFixed(1)}% block rate
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
              <Globe className="w-4 h-4" />
              Bandwidth
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{totalBandwidthInRange.toFixed(2)} GB</div>
            <div className="text-sm text-muted-foreground">
              Current: {usage.bandwidth_mbps.toFixed(2)} Mbps
            </div>
            <div className="mt-2 text-sm text-muted-foreground">
              Limit: {quota.max_bandwidth_mbps > 0 ? `${quota.max_bandwidth_mbps} Mbps` : 'Unlimited'}
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Quota Usage */}
        <Card>
          <CardHeader>
            <CardTitle>Quota Usage</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span className="flex items-center gap-2">
                  <Zap className="w-4 h-4" />
                  Requests per Minute
                </span>
                <span className={usage.quota_percentage > 90 ? 'text-red-600 font-medium' : ''}>
                  {usage.quota_percentage.toFixed(1)}%
                </span>
              </div>
              <div className="h-3 bg-border rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${
                    usage.quota_percentage > 90 ? 'bg-red-500' : usage.quota_percentage > 70 ? 'bg-yellow-500' : 'bg-green-500'
                  }`}
                  style={{ width: `${Math.min(usage.quota_percentage, 100)}%` }}
                />
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                {usage.requests_per_minute.toLocaleString()} / {quota.max_requests_per_minute > 0 ? quota.max_requests_per_minute.toLocaleString() : '∞'} requests
              </div>
            </div>

            <div>
              <div className="flex justify-between text-sm mb-2">
                <span className="flex items-center gap-2">
                  <Globe className="w-4 h-4" />
                  Bandwidth
                </span>
              </div>
              <div className="h-3 bg-border rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full bg-blue-500 transition-all duration-500"
                  style={{ width: `${bandwidthPercent}%` }}
                />
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                {usage.bandwidth_mbps.toFixed(2)} / {quota.max_bandwidth_mbps > 0 ? quota.max_bandwidth_mbps : '∞'} Mbps
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 pt-4 border-t">
              <div className="p-3 bg-muted/10 rounded">
                <div className="text-sm text-muted-foreground flex items-center gap-1">
                  <Shield className="w-3 h-3" />
                  Rules
                </div>
                <div className="text-lg font-semibold">0 / {getQuota(tenant).max_rules || '∞'}</div>
              </div>
              <div className="p-3 bg-muted/10 rounded">
                <div className="text-sm text-muted-foreground flex items-center gap-1">
                  <Ban className="w-3 h-3" />
                  IP ACLs
                </div>
                <div className="text-lg font-semibold">0 / {getQuota(tenant).max_ip_acls || '∞'}</div>
              </div>
              <div className="p-3 bg-muted/10 rounded">
                <div className="text-sm text-muted-foreground flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  Rate Limits
                </div>
                <div className="text-lg font-semibold">0 / {getQuota(tenant).max_rate_limit_rules || '∞'}</div>
              </div>
              <div className="p-3 bg-muted/10 rounded">
                <div className="text-sm text-muted-foreground flex items-center gap-1">
                  <Globe className="w-3 h-3" />
                  Domains
                </div>
                <div className="text-lg font-semibold">{tenant.domains.length} / {getQuota(tenant).max_domains || '∞'}</div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Usage History Chart */}
        <Card>
          <CardHeader>
            <CardTitle>Usage History</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {history.length === 0 && (
                <div className="text-center py-8 text-muted-foreground">
                  <BarChart3 className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">Usage history will appear as traffic is processed.</p>
                  <p className="text-xs mt-1">Data is aggregated per time window and refreshed automatically.</p>
                </div>
              )}
              {history.map((item, index) => (
                <div key={index} className="flex items-center gap-4">
                  <div className="w-16 text-xs text-muted-foreground">
                    {timeRange === '24h'
                      ? new Date(item.date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                      : new Date(item.date).toLocaleDateString([], { month: 'short', day: 'numeric' })}
                  </div>
                  <div className="flex-1">
                    <div className="h-2 bg-border rounded-full overflow-hidden">
                      <div
                        className="h-full bg-accent rounded-full"
                        style={{ width: `${Math.min((item.requests / 20000) * 100, 100)}%` }}
                      />
                    </div>
                  </div>
                  <div className="w-20 text-right text-sm">
                    {item.requests.toLocaleString()}
                  </div>
                  <div className="w-16 text-right text-sm text-red-600">
                    {item.blocked > 0 && `${item.blocked}`}
                  </div>
                </div>
              ))}
            </div>
            <div className="flex justify-between mt-4 pt-4 border-t text-sm text-muted-foreground">
              <span>Total: {totalRequestsInRange.toLocaleString()} requests</span>
              <span>{totalBlockedInRange.toLocaleString()} blocked</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Domains */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="w-5 h-5" />
            Protected Domains ({tenant.domains.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {tenant.domains.map((domain) => (
              <Badge key={domain} variant="outline" className="text-sm py-1 px-3">
                <Globe className="w-3 h-3 mr-1" />
                {domain}
              </Badge>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Footer */}
      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <div className="flex items-center gap-2">
          <Calendar className="w-4 h-4" />
          Created: {new Date(tenant.created_at).toLocaleDateString()}
        </div>
        {usage.last_request_at && (
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4" />
            Last request: {new Date(usage.last_request_at).toLocaleString()}
          </div>
        )}
      </div>
    </div>
  )
}
