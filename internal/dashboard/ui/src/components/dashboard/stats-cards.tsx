import { memo } from 'react'
import { Shield, ShieldOff, ShieldAlert, FileText, CheckCircle, Timer, BellRing } from 'lucide-react'
import { cn, formatNumber, formatDuration } from '@/lib/utils'
import type { Stats } from '@/lib/api'

interface StatsCardsProps {
  stats: Stats
}

const cards = [
  { key: 'total_requests' as const, label: 'Total Requests', hint: 'All requests the WAF has inspected', icon: Shield, color: 'text-accent', bg: 'bg-accent/10' },
  { key: 'blocked_requests' as const, label: 'Blocked', hint: 'Rejected before reaching your app', icon: ShieldOff, color: 'text-destructive', bg: 'bg-destructive/10' },
  { key: 'challenged_requests' as const, label: 'Challenged', hint: 'Suspected bots sent a proof-of-work test', icon: ShieldAlert, color: 'text-orange', bg: 'bg-orange/10' },
  { key: 'logged_requests' as const, label: 'Logged', hint: 'Suspicious but allowed; recorded only', icon: FileText, color: 'text-warning', bg: 'bg-warning/10' },
  { key: 'passed_requests' as const, label: 'Passed', hint: 'Clean requests forwarded as-is', icon: CheckCircle, color: 'text-success', bg: 'bg-success/10' },
]

export const StatsCards = memo(function StatsCards({ stats }: StatsCardsProps) {
  const total = stats.total_requests || 1
  const hasAlerting = stats.alerting && (stats.alerting.webhook_count > 0 || stats.alerting.email_count > 0)

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map(({ key, label, hint, icon: Icon, color, bg }) => {
        const value = stats[key]
        const pct = key !== 'total_requests' ? ((value / total) * 100).toFixed(1) + '%' : ''

        return (
          <div
            key={key}
            className="rounded-lg border border-border bg-card p-4 transition-all hover:shadow-md hover:-translate-y-0.5"
            role="status"
            title={hint}
            aria-label={`${label}: ${formatNumber(value)}${pct ? ` (${pct})` : ''}`}
          >
            <div className="flex items-center gap-2 mb-2">
              <div className={cn('flex h-8 w-8 items-center justify-center rounded-md', bg)}>
                <Icon className={cn('h-4 w-4', color)} />
              </div>
              <span className="text-xs text-muted-foreground">{label}</span>
            </div>
            <div className="text-2xl font-bold tracking-tight">{formatNumber(value)}</div>
            {pct && <div className="text-xs text-muted mt-1">{pct}</div>}
          </div>
        )
      })}

      {/* Latency card */}
      <div title="Average time the WAF adds to each request" className="rounded-lg border border-border bg-card p-4 transition-all hover:shadow-md hover:-translate-y-0.5">
        <div className="flex items-center gap-2 mb-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-purple-500/10">
            <Timer className="h-4 w-4 text-purple-400" />
          </div>
          <span className="text-xs text-muted-foreground">Avg Latency</span>
        </div>
        <div className="text-2xl font-bold tracking-tight">{formatDuration(stats.avg_latency_us)}</div>
      </div>

      {/* Alerting stats */}
      {hasAlerting && (
        <div className="rounded-lg border border-border bg-card p-4 transition-all hover:shadow-md hover:-translate-y-0.5 col-span-2 md:col-span-3 lg:col-span-2">
          <div className="flex items-center gap-2 mb-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-blue-500/10">
              <BellRing className="h-4 w-4 text-blue-400" />
            </div>
            <span className="text-xs text-muted-foreground">Alerting</span>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <div className="text-lg font-bold tracking-tight">{formatNumber(stats.alerting!.sent)}</div>
              <div className="text-xs text-muted">Sent</div>
            </div>
            <div>
              <div className="text-lg font-bold tracking-tight text-destructive">{formatNumber(stats.alerting!.failed)}</div>
              <div className="text-xs text-muted">Failed</div>
            </div>
          </div>
          <div className="text-xs text-muted mt-1">
            {stats.alerting!.webhook_count} webhooks, {stats.alerting!.email_count} emails
          </div>
        </div>
      )}
    </div>
  )
})
