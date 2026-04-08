import { useState, useEffect } from 'react'
import { useParams } from 'react-router'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { useToast } from '@/components/ui/toast'
import { api, Tenant, TenantUsage as TenantUsageType } from '@/lib/api'
import {
  ArrowLeft,
  RefreshCw,
  Download,
  Activity,
  Shield,
  Globe,
  BarChart3,
  DollarSign,
  TrendingUp,
  AlertTriangle,
  Calendar,
  Clock,
  Zap,
  Ban
} from 'lucide-react'

// Helper to safely access tenant quota with defaults
const getQuota = (tenant: Tenant) => ({
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

interface BillingEstimate {
  plan_cost: number
  overage_cost: number
  total_cost: number
  currency: string
  breakdown: {
    requests_overages: number
    bandwidth_overages: number
  }
}

const PLAN_PRICES: Record<string, number> = {
  free: 0,
  basic: 49,
  pro: 199,
  enterprise: 0 // Custom pricing
}

const OVERAGE_RATES = {
  requests_per_million: 5, // $5 per million requests over quota
  bandwidth_per_gb: 0.10   // $0.10 per GB over quota
}

export default function TenantAnalyticsPage() {
  const { id } = useParams<{ id: string }>()
  const [loading, setLoading] = useState(true)
  const [tenant, setTenant] = useState<Tenant | null>(null)
  const [usage, setUsage] = useState<TenantUsageType | null>(null)
  const [history, setHistory] = useState<UsageHistory[]>([])
  const [refreshing, setRefreshing] = useState(false)
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d'>('24h')
  const { toast } = useToast()

  const loadData = async () => {
    try {
      const [tenantData, usageData] = await Promise.all([
        api.getTenant(id!),
        api.getTenantUsage(id!)
      ])
      setTenant(tenantData)
      setUsage(usageData)

      // Generate mock history data for demonstration
      const mockHistory: UsageHistory[] = generateMockHistory(timeRange)
      setHistory(mockHistory)
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to load tenant analytics',
        variant: 'destructive'
      })
    } finally {
      setLoading(false)
    }
  }

  const generateMockHistory = (range: '24h' | '7d' | '30d'): UsageHistory[] => {
    const now = new Date()
    const data: UsageHistory[] = []

    const points = range === '24h' ? 24 : range === '7d' ? 7 : 30
    const interval = range === '24h' ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000

    for (let i = points - 1; i >= 0; i--) {
      const date = new Date(now.getTime() - i * interval)
      data.push({
        date: date.toISOString(),
        requests: Math.floor(Math.random() * 10000) + 5000,
        blocked: Math.floor(Math.random() * 500),
        bandwidth_gb: Math.random() * 10 + 1
      })
    }

    return data
  }

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
        plan: tenant.plan || 'basic',
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
      billing: calculateBilling(),
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

  const calculateBilling = (): BillingEstimate => {
    if (!tenant || !usage) {
      return { plan_cost: 0, overage_cost: 0, total_cost: 0, currency: 'USD', breakdown: { requests_overages: 0, bandwidth_overages: 0 } }
    }

    const planCost = PLAN_PRICES[tenant.plan || 'basic'] || 0

    // Calculate overages
    const monthlyRequests = usage.total_requests
    const monthlyBandwidthGB = usage.bytes_transferred / (1024 * 1024 * 1024)

    // Assume monthly quota limits (simplified)
    const quota = getQuota(tenant)
    const monthlyRequestQuota = quota.max_requests_per_minute * 60 * 24 * 30 // per month
    const monthlyBandwidthQuota = quota.max_bandwidth_mbps * 60 * 60 * 24 * 30 / 8000 // convert to GB/month roughly

    const requestOverages = Math.max(0, monthlyRequests - monthlyRequestQuota)
    const bandwidthOverages = Math.max(0, monthlyBandwidthGB - monthlyBandwidthQuota)

    const requestOverageCost = (requestOverages / 1000000) * OVERAGE_RATES.requests_per_million
    const bandwidthOverageCost = bandwidthOverages * OVERAGE_RATES.bandwidth_per_gb

    return {
      plan_cost: planCost,
      overage_cost: requestOverageCost + bandwidthOverageCost,
      total_cost: planCost + requestOverageCost + bandwidthOverageCost,
      currency: 'USD',
      breakdown: {
        requests_overages: requestOverageCost,
        bandwidth_overages: bandwidthOverageCost
      }
    }
  }

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 30000) // Refresh every 30s
    return () => clearInterval(interval)
  }, [id, timeRange])

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
        <Button onClick={() => window.location.href = '/tenants'}>
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Tenants
        </Button>
      </div>
    )
  }

  const billing = calculateBilling()
  const blockedPercentage = usage.total_requests > 0
    ? (usage.blocked_requests / usage.total_requests * 100).toFixed(1)
    : '0'

  const getStatusBg = (status: string) => {
    switch (status) {
      case 'ok': return 'bg-green-50 border-green-200 dark:bg-green-900/20 dark:border-green-800'
      case 'warning': return 'bg-yellow-50 border-yellow-200 dark:bg-yellow-900/20 dark:border-yellow-800'
      case 'exceeded': return 'bg-red-50 border-red-200 dark:bg-red-900/20 dark:border-red-800'
      default: return 'bg-gray-50 border-gray-200'
    }
  }

  const totalRequestsInRange = history.reduce((sum, h) => sum + h.requests, 0)
  const totalBlockedInRange = history.reduce((sum, h) => sum + h.blocked, 0)
  const totalBandwidthInRange = history.reduce((sum, h) => sum + h.bandwidth_gb, 0)

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-4">
          <Button variant="ghost" onClick={() => window.location.href = '/tenants'}>
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back
          </Button>
          <div>
            <h1 className="text-3xl font-bold">{tenant.name}</h1>
            <div className="flex items-center gap-2 text-sm text-gray-500">
              <span>Usage Analytics & Billing</span>
              <Badge variant={tenant.active ? 'default' : 'secondary'}>
                {tenant.active ? 'Active' : 'Inactive'}
              </Badge>
              <Badge variant="outline">{tenant.plan || 'basic'}</Badge>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center bg-gray-100 dark:bg-gray-800 rounded-lg p-1">
            {(['24h', '7d', '30d'] as const).map((range) => (
              <button
                key={range}
                onClick={() => setTimeRange(range)}
                className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
                  timeRange === range
                    ? 'bg-white dark:bg-gray-700 shadow-sm'
                    : 'text-gray-500 hover:text-gray-700'
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
          <Button onClick={() => window.location.href = `/tenants/${id}`}>
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
            <div className="text-sm text-gray-600 dark:text-gray-400">
              {usage.quota_status === 'exceeded'
                ? 'This tenant has exceeded their rate limit quota. Consider upgrading their plan.'
                : usage.quota_status === 'warning'
                ? `${usage.quota_percentage.toFixed(1)}% of quota used. Monitor closely.`
                : 'Usage is within normal parameters.'}
            </div>
          </div>
          {usage.quota_status !== 'ok' && (
            <Button size="sm" variant="default">
              Upgrade Plan
            </Button>
          )}
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-gray-500 flex items-center gap-2">
              <Activity className="w-4 h-4" />
              Requests/min
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{usage.requests_per_minute.toLocaleString()}</div>
            <div className="text-sm text-gray-500">
              Limit: {getQuota(tenant).max_requests_per_minute > 0 ? getQuota(tenant).max_requests_per_minute.toLocaleString() : '∞'}
            </div>
            <div className="mt-2 h-1.5 bg-gray-200 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${usage.quota_percentage > 90 ? 'bg-red-500' : usage.quota_percentage > 70 ? 'bg-yellow-500' : 'bg-green-500'}`}
                style={{ width: `${Math.min(usage.quota_percentage, 100)}%` }}
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-gray-500 flex items-center gap-2">
              <BarChart3 className="w-4 h-4" />
              Total Requests ({timeRange})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{totalRequestsInRange.toLocaleString()}</div>
            <div className="text-sm text-gray-500">
              {blockedPercentage}% blocked
            </div>
            <div className="mt-2 flex items-center gap-2 text-sm">
              <TrendingUp className="w-4 h-4 text-green-500" />
              <span className="text-green-600">+12% from last period</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-gray-500 flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Threats Blocked
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-600">{totalBlockedInRange.toLocaleString()}</div>
            <div className="text-sm text-gray-500">
              {usage.blocked_requests.toLocaleString()} all-time
            </div>
            <div className="mt-2 text-sm text-gray-500">
              {((totalBlockedInRange / (totalRequestsInRange || 1)) * 100).toFixed(1)}% block rate
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-gray-500 flex items-center gap-2">
              <Globe className="w-4 h-4" />
              Bandwidth
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{totalBandwidthInRange.toFixed(2)} GB</div>
            <div className="text-sm text-gray-500">
              Current: {usage.bandwidth_mbps.toFixed(2)} Mbps
            </div>
            <div className="mt-2 text-sm text-gray-500">
              Limit: {getQuota(tenant).max_bandwidth_mbps > 0 ? `${getQuota(tenant).max_bandwidth_mbps} Mbps` : 'Unlimited'}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Billing Overview */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <DollarSign className="w-5 h-5" />
            Billing Overview
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="space-y-4">
              <div className="text-sm text-gray-500">Current Plan</div>
              <div className="text-2xl font-bold capitalize">{tenant.plan || 'basic'}</div>
              <div className="text-3xl font-bold text-accent">
                ${billing.plan_cost}
                <span className="text-sm text-gray-500 font-normal">/month</span>
              </div>
            </div>

            <div className="space-y-4">
              <div className="text-sm text-gray-500">Overages</div>
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Request overages</span>
                  <span>${billing.breakdown.requests_overages.toFixed(2)}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>Bandwidth overages</span>
                  <span>${billing.breakdown.bandwidth_overages.toFixed(2)}</span>
                </div>
                <div className="flex justify-between font-medium pt-2 border-t">
                  <span>Total overages</span>
                  <span className={billing.overage_cost > 0 ? 'text-red-600' : ''}>
                    ${billing.overage_cost.toFixed(2)}
                  </span>
                </div>
              </div>
            </div>

            <div className="space-y-4">
              <div className="text-sm text-gray-500">Estimated Total</div>
              <div className={`text-4xl font-bold ${billing.overage_cost > 0 ? 'text-red-600' : 'text-green-600'}`}>
                ${billing.total_cost.toFixed(2)}
              </div>
              <div className="text-sm text-gray-500">Current month projection</div>
            </div>
          </div>

          {billing.overage_cost > 0 && (
            <div className="mt-6 p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-yellow-600" />
              <div className="text-sm">
                <strong>Overage charges detected.</strong> Consider upgrading to a higher plan to save costs.
              </div>
            </div>
          )}
        </CardContent>
      </Card>

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
              <div className="h-3 bg-gray-200 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${
                    usage.quota_percentage > 90 ? 'bg-red-500' : usage.quota_percentage > 70 ? 'bg-yellow-500' : 'bg-green-500'
                  }`}
                  style={{ width: `${Math.min(usage.quota_percentage, 100)}%` }}
                />
              </div>
              <div className="text-xs text-gray-500 mt-1">
                {usage.requests_per_minute.toLocaleString()} / {getQuota(tenant).max_requests_per_minute.toLocaleString()} requests
              </div>
            </div>

            <div>
              <div className="flex justify-between text-sm mb-2">
                <span className="flex items-center gap-2">
                  <Globe className="w-4 h-4" />
                  Bandwidth
                </span>
              </div>
              <div className="h-3 bg-gray-200 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full bg-blue-500 transition-all duration-500"
                  style={{ width: `${Math.min((usage.bandwidth_mbps / getQuota(tenant).max_bandwidth_mbps) * 100, 100)}%` }}
                />
              </div>
              <div className="text-xs text-gray-500 mt-1">
                {usage.bandwidth_mbps.toFixed(2)} / {getQuota(tenant).max_bandwidth_mbps} Mbps
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4 pt-4 border-t">
              <div className="p-3 bg-gray-50 dark:bg-gray-800 rounded">
                <div className="text-sm text-gray-500 flex items-center gap-1">
                  <Shield className="w-3 h-3" />
                  Rules
                </div>
                <div className="text-lg font-semibold">0 / {getQuota(tenant).max_rules || '∞'}</div>
              </div>
              <div className="p-3 bg-gray-50 dark:bg-gray-800 rounded">
                <div className="text-sm text-gray-500 flex items-center gap-1">
                  <Ban className="w-3 h-3" />
                  IP ACLs
                </div>
                <div className="text-lg font-semibold">0 / {getQuota(tenant).max_ip_acls || '∞'}</div>
              </div>
              <div className="p-3 bg-gray-50 dark:bg-gray-800 rounded">
                <div className="text-sm text-gray-500 flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  Rate Limits
                </div>
                <div className="text-lg font-semibold">0 / {getQuota(tenant).max_rate_limit_rules || '∞'}</div>
              </div>
              <div className="p-3 bg-gray-50 dark:bg-gray-800 rounded">
                <div className="text-sm text-gray-500 flex items-center gap-1">
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
              {history.map((item, index) => (
                <div key={index} className="flex items-center gap-4">
                  <div className="w-16 text-xs text-gray-500">
                    {timeRange === '24h'
                      ? new Date(item.date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                      : new Date(item.date).toLocaleDateString([], { month: 'short', day: 'numeric' })}
                  </div>
                  <div className="flex-1">
                    <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
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
            <div className="flex justify-between mt-4 pt-4 border-t text-sm text-gray-500">
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
      <div className="flex items-center justify-between text-sm text-gray-500">
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
