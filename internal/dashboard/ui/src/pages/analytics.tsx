import { useEffect, useMemo, useState } from 'react'
import { Activity, Ban, BarChart3, Clock, ShieldAlert, Users } from 'lucide-react'
import { api } from '@/lib/api'
import type { Stats, WafEvent } from '@/lib/api'

const periods = [
  { value: '1h', label: 'Last hour' },
  { value: '24h', label: 'Last day' },
  { value: '7d', label: 'Last 7 days' },
]

function periodStart(period: string) {
  const now = Date.now()
  if (period === '7d') return now - 7 * 24 * 60 * 60 * 1000
  if (period === '24h') return now - 24 * 60 * 60 * 1000
  return now - 60 * 60 * 1000
}

export default function AnalyticsPage() {
  const [period, setPeriod] = useState('1h')
  const [stats, setStats] = useState<Stats | null>(null)
  const [events, setEvents] = useState<WafEvent[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const start = periodStart(period)
    const end = Date.now()
    Promise.all([
      api.getStats(),
      api.getEvents({ start: String(start), end: String(end), limit: '200' }),
    ])
      .then(([statsData, eventsData]) => {
        setStats(statsData)
        setEvents(eventsData.events || [])
      })
      .finally(() => setLoading(false))
  }, [period])

  const topIPs = useMemo(() => {
    const counts = new Map<string, number>()
    for (const event of events) {
      if (!event.client_ip) continue
      counts.set(event.client_ip, (counts.get(event.client_ip) || 0) + 1)
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5)
  }, [events])

  const attacks = events.filter((event) => event.action === 'block' || event.score >= 50).length

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <BarChart3 className="h-5 w-5 text-accent" />
          <h1 className="text-lg font-semibold">Analytics</h1>
        </div>
        <label className="flex items-center gap-2 text-xs text-muted">
          <Clock className="h-4 w-4" />
          Period
          <select
            value={period}
            onChange={(e) => {
              setLoading(true)
              setPeriod(e.target.value)
            }}
            className="h-8 rounded-md border border-border bg-background px-2 text-xs text-foreground outline-none focus:ring-1 focus:ring-accent"
          >
            {periods.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
          </select>
        </label>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Metric icon={Activity} label="Requests" value={stats?.total_requests ?? 0} />
        <Metric icon={Ban} label="Blocked" value={stats?.blocked_requests ?? 0} />
        <Metric icon={ShieldAlert} label="Attacks" value={attacks} />
        <Metric icon={Users} label="Unique IPs" value={topIPs.length} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="rounded-lg border border-border bg-card p-4">
          <h2 className="mb-3 text-sm font-semibold">Traffic Mix</h2>
          <div className="space-y-2 text-sm">
            <Bar label="Passed" value={stats?.passed_requests ?? 0} total={stats?.total_requests ?? 0} className="bg-success" />
            <Bar label="Logged" value={stats?.logged_requests ?? 0} total={stats?.total_requests ?? 0} className="bg-warning" />
            <Bar label="Challenged" value={stats?.challenged_requests ?? 0} total={stats?.total_requests ?? 0} className="bg-accent" />
            <Bar label="Blocked" value={stats?.blocked_requests ?? 0} total={stats?.total_requests ?? 0} className="bg-destructive" />
          </div>
        </section>

        <section className="rounded-lg border border-border bg-card p-4">
          <h2 className="mb-3 text-sm font-semibold">Top Sources</h2>
          {loading ? (
            <p className="py-8 text-center text-sm text-muted">Loading analytics...</p>
          ) : topIPs.length === 0 ? (
            <p className="py-8 text-center text-sm text-muted">No source data for this period.</p>
          ) : (
            <div className="space-y-2">
              {topIPs.map(([ip, count]) => (
                <div key={ip} className="flex items-center justify-between rounded-md bg-background px-3 py-2 text-sm">
                  <span className="font-mono">{ip}</span>
                  <span className="text-muted">{count}</span>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  )
}

function Metric({ icon: Icon, label, value }: { icon: typeof Activity; label: string; value: number }) {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="mb-2 flex items-center gap-2 text-xs text-muted">
        <Icon className="h-4 w-4" />
        {label}
      </div>
      <div className="text-2xl font-semibold">{value.toLocaleString()}</div>
    </div>
  )
}

function Bar({ label, value, total, className }: { label: string; value: number; total: number; className: string }) {
  const pct = total > 0 ? Math.round((value / total) * 100) : 0
  return (
    <div>
      <div className="mb-1 flex justify-between text-xs text-muted">
        <span>{label}</span>
        <span>{value.toLocaleString()} ({pct}%)</span>
      </div>
      <div className="h-2 rounded-full bg-background">
        <div className={`h-2 rounded-full ${className}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}
