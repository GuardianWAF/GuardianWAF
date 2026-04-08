import { useState, useEffect, useCallback, useRef } from 'react'
import { api } from '@/lib/api'
import type { Stats, WafEvent, UpstreamStatus } from '@/lib/api'
import { StatsCards } from '@/components/dashboard/stats-cards'
import { TrafficChart } from '@/components/dashboard/traffic-chart'
import { EventsTable } from '@/components/dashboard/events-table'
import { UpstreamHealth } from '@/components/dashboard/upstream-health'
import { TopIPs } from '@/components/dashboard/top-ips'
import { Button } from '@/components/ui/button'
import { useToast } from '@/components/ui/toast'
import {
  Activity,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Wifi,
  WifiOff,
  Shield,
  Zap,
  BarChart3
} from 'lucide-react'

interface SystemHealth {
  status: 'healthy' | 'degraded' | 'unhealthy'
  message: string
  lastCheck: Date
  components: {
    engine: boolean
    proxy: boolean
    eventStore: boolean
    sse: boolean
  }
}

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats>({
    total_requests: 0, blocked_requests: 0, challenged_requests: 0,
    logged_requests: 0, passed_requests: 0, avg_latency_us: 0,
  })
  const [events, setEvents] = useState<WafEvent[]>([])
  const [upstreams, setUpstreams] = useState<UpstreamStatus[]>([])
  const [filter, setFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [sseConnected, setSseConnected] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [lastError, setLastError] = useState<string | null>(null)
  const [systemHealth, setSystemHealth] = useState<SystemHealth>({
    status: 'healthy',
    message: 'All systems operational',
    lastCheck: new Date(),
    components: { engine: true, proxy: true, eventStore: true, sse: false }
  })
  const [refreshInterval] = useState(5000)
  const sseRef = useRef<EventSource | null>(null)
  const retryDelay = useRef(1000)
  const consecutiveErrors = useRef(0)
  const { toast } = useToast()

  // Health check function
  const checkHealth = useCallback(async () => {
    try {
      const [statsData, upstreamsData] = await Promise.all([
        api.getStats(),
        api.getUpstreams()
      ])

      setStats(statsData)
      setUpstreams(upstreamsData)

      // Determine system health
      const components = {
        engine: true,
        proxy: upstreamsData.length > 0 ? upstreamsData.some(u => u.healthy_count > 0) : true,
        eventStore: true,
        sse: sseConnected
      }

      const healthyCount = Object.values(components).filter(Boolean).length
      let status: SystemHealth['status'] = 'healthy'
      let message = 'All systems operational'

      if (healthyCount < 4) {
        status = 'degraded'
        message = 'Some components experiencing issues'
      }
      if (healthyCount < 2) {
        status = 'unhealthy'
        message = 'System experiencing significant issues'
      }

      setSystemHealth({
        status,
        message,
        lastCheck: new Date(),
        components
      })

      consecutiveErrors.current = 0
      setLastError(null)
    } catch (err: any) {
      consecutiveErrors.current++
      setLastError(err.message || 'Connection error')

      if (consecutiveErrors.current >= 3) {
        setSystemHealth(prev => ({
          ...prev,
          status: 'unhealthy',
          message: 'Failed to connect to backend',
          lastCheck: new Date()
        }))
      }

      if (consecutiveErrors.current === 1) {
        toast({
          title: 'Connection Issue',
          description: 'Having trouble connecting to the server. Retrying...',
          variant: 'destructive'
        })
      }
    }
  }, [sseConnected, toast])

  // Initial data load
  useEffect(() => {
    setIsLoading(true)
    Promise.all([
      api.getStats(),
      api.getEvents({ limit: '50' }),
      api.getUpstreams()
    ])
      .then(([statsData, eventsData, upstreamsData]) => {
        setStats(statsData)
        setEvents(eventsData.events || [])
        setUpstreams(upstreamsData)
        setIsLoading(false)
      })
      .catch((err) => {
        setLastError(err.message)
        setIsLoading(false)
        toast({
          title: 'Error',
          description: 'Failed to load dashboard data',
          variant: 'destructive'
        })
      })
  }, [toast])

  // Polling with adaptive interval
  useEffect(() => {
    const interval = setInterval(() => {
      checkHealth()
    }, refreshInterval)
    return () => clearInterval(interval)
  }, [checkHealth, refreshInterval])

  // Add event from SSE
  const addEvent = useCallback((event: WafEvent) => {
    setEvents(prev => [event, ...prev].slice(0, 200))
    setStats(prev => {
      const next = { ...prev, total_requests: prev.total_requests + 1 }
      if (event.action === 'block') next.blocked_requests++
      else if (event.action === 'challenge') next.challenged_requests++
      else if (event.action === 'log') next.logged_requests++
      else next.passed_requests++
      return next
    })
  }, [])

  // SSE connection with reconnection logic
  useEffect(() => {
    function connect() {
      try {
        const sse = new EventSource('/api/v1/sse')
        sseRef.current = sse

        sse.onopen = () => {
          setSseConnected(true)
          retryDelay.current = 1000
          consecutiveErrors.current = 0
        }

        sse.onmessage = (e) => {
          try {
            const data = JSON.parse(e.data)
            if (data.action && data.client_ip) addEvent(data as WafEvent)
          } catch { /* ignore parse errors */ }
        }

        sse.onerror = () => {
          setSseConnected(false)
          sse.close()
          sseRef.current = null

          const delay = retryDelay.current
          retryDelay.current = Math.min(delay * 2, 30000)
          setTimeout(connect, delay)
        }
      } catch (err) {
        setSseConnected(false)
        setTimeout(connect, retryDelay.current)
      }
    }

    connect()
    return () => { sseRef.current?.close() }
  }, [addEvent])

  // Manual refresh handler
  const handleRefresh = async () => {
    setIsLoading(true)
    await checkHealth()
    try {
      const eventsData = await api.getEvents({ limit: '50' })
      setEvents(eventsData.events || [])
      toast({ title: 'Refreshed', description: 'Dashboard data updated' })
    } catch (err: any) {
      toast({
        title: 'Error',
        description: err.message || 'Failed to refresh',
        variant: 'destructive'
      })
    } finally {
      setIsLoading(false)
    }
  }

  // Get health color
  const getHealthColor = (status: SystemHealth['status']) => {
    switch (status) {
      case 'healthy': return 'text-green-500 bg-green-50 dark:bg-green-900/20 border-green-200'
      case 'degraded': return 'text-yellow-500 bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200'
      case 'unhealthy': return 'text-red-500 bg-red-50 dark:bg-red-900/20 border-red-200'
    }
  }

  const getHealthIcon = (status: SystemHealth['status']) => {
    switch (status) {
      case 'healthy': return <CheckCircle className="w-5 h-5" />
      case 'degraded': return <AlertTriangle className="w-5 h-5" />
      case 'unhealthy': return <WifiOff className="w-5 h-5" />
    }
  }

  if (isLoading && events.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-96 space-y-4">
        <div className="animate-spin h-12 w-12 border-4 border-accent border-t-transparent rounded-full" />
        <p className="text-muted-foreground">Loading dashboard...</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header with System Health */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-accent" />
          <div>
            <h1 className="text-2xl font-bold">GuardianWAF Dashboard</h1>
            <p className="text-sm text-muted-foreground">
              Real-time security monitoring and analytics
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Health Status */}
          <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${getHealthColor(systemHealth.status)}`}>
            {getHealthIcon(systemHealth.status)}
            <div className="text-sm">
              <div className="font-medium capitalize">{systemHealth.status}</div>
              <div className="text-xs opacity-75">{systemHealth.message}</div>
            </div>
          </div>

          {/* SSE Status */}
          <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${
            sseConnected
              ? 'text-green-600 bg-green-50 dark:bg-green-900/20 border-green-200'
              : 'text-red-600 bg-red-50 dark:bg-red-900/20 border-red-200'
          }`}>
            {sseConnected ? <Wifi className="w-4 h-4" /> : <WifiOff className="w-4 h-4" />}
            <span className="text-sm font-medium">{sseConnected ? 'Live' : 'Offline'}</span>
          </div>

          {/* Refresh Button */}
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            disabled={isLoading}
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Error Banner */}
      {lastError && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 text-red-600" />
          <div className="flex-1">
            <p className="font-medium text-red-800">Connection Error</p>
            <p className="text-sm text-red-700">{lastError}</p>
          </div>
          <Button variant="outline" size="sm" onClick={handleRefresh}>
            Retry
          </Button>
        </div>
      )}

      {/* Quick Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-accent/10 rounded-lg p-4 flex items-center gap-3">
          <div className="p-2 bg-accent/20 rounded-lg">
            <Activity className="w-5 h-5 text-accent" />
          </div>
          <div>
            <div className="text-2xl font-bold">{stats.total_requests.toLocaleString()}</div>
            <div className="text-xs text-muted-foreground">Total Requests</div>
          </div>
        </div>

        <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-4 flex items-center gap-3">
          <div className="p-2 bg-red-100 dark:bg-red-800 rounded-lg">
            <Shield className="w-5 h-5 text-red-600" />
          </div>
          <div>
            <div className="text-2xl font-bold text-red-600">{stats.blocked_requests.toLocaleString()}</div>
            <div className="text-xs text-muted-foreground">Blocked</div>
          </div>
        </div>

        <div className="bg-yellow-50 dark:bg-yellow-900/20 rounded-lg p-4 flex items-center gap-3">
          <div className="p-2 bg-yellow-100 dark:bg-yellow-800 rounded-lg">
            <Zap className="w-5 h-5 text-yellow-600" />
          </div>
          <div>
            <div className="text-2xl font-bold text-yellow-600">{stats.challenged_requests.toLocaleString()}</div>
            <div className="text-xs text-muted-foreground">Challenged</div>
          </div>
        </div>

        <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4 flex items-center gap-3">
          <div className="p-2 bg-blue-100 dark:bg-blue-800 rounded-lg">
            <BarChart3 className="w-5 h-5 text-blue-600" />
          </div>
          <div>
            <div className="text-2xl font-bold text-blue-600">
              {stats.avg_latency_us > 0 ? `${(stats.avg_latency_us / 1000).toFixed(2)}ms` : '-'}
            </div>
            <div className="text-xs text-muted-foreground">Avg Latency</div>
          </div>
        </div>
      </div>

      <StatsCards stats={stats} />
      <TrafficChart events={events} minutes={30} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <UpstreamHealth upstreams={upstreams} />
        <TopIPs events={events} />
      </div>

      <EventsTable
        events={events}
        filter={filter}
        setFilter={setFilter}
        search={search}
        setSearch={setSearch}
        isLoading={isLoading}
      />

      {/* Footer */}
      <div className="text-center text-xs text-muted-foreground pt-4 border-t">
        <p>Last updated: {systemHealth.lastCheck.toLocaleTimeString()}</p>
        <p className="mt-1">
          GuardianWAF v1.0 • {sseConnected ? 'Real-time updates active' : 'Real-time updates disconnected'}
        </p>
      </div>
    </div>
  )
}
