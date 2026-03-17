import { Shield, ShieldOff, ShieldAlert, FileText, CheckCircle, Timer } from 'lucide-react'
import { cn, formatNumber, formatDuration } from '@/lib/utils'
import type { Stats } from '@/lib/api'

interface StatsCardsProps {
  stats: Stats
}

const cards = [
  { key: 'total_requests' as const, label: 'Total Requests', icon: Shield, color: 'text-accent', bg: 'bg-accent/10' },
  { key: 'blocked_requests' as const, label: 'Blocked', icon: ShieldOff, color: 'text-destructive', bg: 'bg-destructive/10' },
  { key: 'challenged_requests' as const, label: 'Challenged', icon: ShieldAlert, color: 'text-orange', bg: 'bg-orange/10' },
  { key: 'logged_requests' as const, label: 'Logged', icon: FileText, color: 'text-warning', bg: 'bg-warning/10' },
  { key: 'passed_requests' as const, label: 'Passed', icon: CheckCircle, color: 'text-success', bg: 'bg-success/10' },
]

export function StatsCards({ stats }: StatsCardsProps) {
  const total = stats.total_requests || 1

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map(({ key, label, icon: Icon, color, bg }) => {
        const value = stats[key]
        const pct = key !== 'total_requests' ? ((value / total) * 100).toFixed(1) + '%' : ''

        return (
          <div
            key={key}
            className="rounded-lg border border-border bg-card p-4 transition-all hover:shadow-md hover:-translate-y-0.5"
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
      <div className="rounded-lg border border-border bg-card p-4 transition-all hover:shadow-md hover:-translate-y-0.5">
        <div className="flex items-center gap-2 mb-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-purple-500/10">
            <Timer className="h-4 w-4 text-purple-400" />
          </div>
          <span className="text-xs text-muted-foreground">Avg Latency</span>
        </div>
        <div className="text-2xl font-bold tracking-tight">{formatDuration(stats.avg_latency_us)}</div>
      </div>
    </div>
  )
}
