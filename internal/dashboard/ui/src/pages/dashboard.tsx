import { useState, useEffect, useCallback, useRef } from 'react'
import { api } from '@/lib/api'
import type { Stats, WafEvent, UpstreamStatus } from '@/lib/api'
import { StatsCards } from '@/components/dashboard/stats-cards'
import { EventsTable } from '@/components/dashboard/events-table'
import { UpstreamHealth } from '@/components/dashboard/upstream-health'
import { TopIPs } from '@/components/dashboard/top-ips'

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
  const sseRef = useRef<EventSource | null>(null)
  const retryDelay = useRef(1000)

  // Fetch initial data
  useEffect(() => {
    api.getStats().then(setStats).catch(() => {})
    api.getEvents({ limit: '50' }).then(data => setEvents(data.events || [])).catch(() => {})
    api.getUpstreams().then(setUpstreams).catch(() => {})
  }, [])

  // Poll stats + upstreams
  useEffect(() => {
    const interval = setInterval(() => {
      api.getStats().then(setStats).catch(() => {})
      api.getUpstreams().then(setUpstreams).catch(() => {})
    }, 5000)
    return () => clearInterval(interval)
  }, [])

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

  // SSE connection
  useEffect(() => {
    function connect() {
      const sse = new EventSource('/api/v1/sse')
      sseRef.current = sse
      sse.onopen = () => { setSseConnected(true); retryDelay.current = 1000 }
      sse.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data)
          if (data.action && data.client_ip) addEvent(data as WafEvent)
        } catch { /* ignore */ }
      }
      sse.onerror = () => {
        setSseConnected(false); sse.close(); sseRef.current = null
        const delay = retryDelay.current
        retryDelay.current = Math.min(delay * 2, 30000)
        setTimeout(connect, delay)
      }
    }
    connect()
    return () => { sseRef.current?.close() }
  }, [addEvent])

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 text-xs text-muted">
        <span className={`h-2 w-2 rounded-full ${sseConnected ? 'bg-success animate-pulse' : 'bg-destructive'}`} />
        {sseConnected ? 'Live' : 'Reconnecting...'}
      </div>

      <StatsCards stats={stats} />
      <UpstreamHealth upstreams={upstreams} />

      <div className="grid grid-cols-1 lg:grid-cols-1 gap-4">
        <TopIPs events={events} />
      </div>

      <EventsTable events={events} filter={filter} setFilter={setFilter} search={search} setSearch={setSearch} />
    </div>
  )
}
