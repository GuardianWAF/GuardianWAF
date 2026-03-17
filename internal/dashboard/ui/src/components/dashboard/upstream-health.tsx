import { Server, Activity, CircleOff, CircleDot } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { UpstreamStatus } from '@/lib/api'

interface UpstreamHealthProps {
  upstreams: UpstreamStatus[]
}

export function UpstreamHealth({ upstreams }: UpstreamHealthProps) {
  if (upstreams.length === 0) return null

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
        <Server className="h-4 w-4 text-muted" />
        <h3 className="text-sm font-semibold">Upstream Health</h3>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 p-4">
        {upstreams.map((us, i) => (
          <UpstreamCard key={i} upstream={us} />
        ))}
      </div>
    </div>
  )
}

function UpstreamCard({ upstream: us }: { upstream: UpstreamStatus }) {
  const allHealthy = us.healthy_count === us.total_count
  const someHealthy = us.healthy_count > 0
  const statusColor = allHealthy ? 'text-success' : someHealthy ? 'text-warning' : 'text-destructive'
  const statusBg = allHealthy ? 'bg-success/10' : someHealthy ? 'bg-warning/10' : 'bg-destructive/10'

  return (
    <div className="rounded-md border border-border bg-background p-3">
      <div className="flex items-center justify-between mb-3">
        <div>
          <div className="font-medium text-sm">{us.name}</div>
          <div className="text-xs text-muted">{us.strategy}</div>
        </div>
        <span className={cn('text-xs font-medium px-2 py-0.5 rounded-full', statusBg, statusColor)}>
          {us.healthy_count}/{us.total_count}
        </span>
      </div>
      <div className="space-y-1.5">
        {us.targets.map((t, i) => (
          <div key={i} className="flex items-center justify-between text-xs rounded bg-card px-2 py-1.5">
            <span className="font-mono text-foreground truncate mr-2">{t.url}</span>
            <div className="flex items-center gap-2 shrink-0">
              {t.weight > 1 && <span className="text-muted">w:{t.weight}</span>}
              <span className="text-muted">{t.active_conns} conn</span>
              <HealthDot healthy={t.healthy} circuit={t.circuit_state} />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function HealthDot({ healthy, circuit }: { healthy: boolean; circuit: string }) {
  if (circuit === 'half-open') {
    return <span title="Half-open"><CircleDot className="h-3 w-3 text-warning" /></span>
  }
  if (!healthy) {
    return <span title="Unhealthy"><CircleOff className="h-3 w-3 text-destructive" /></span>
  }
  return <span title="Healthy"><Activity className="h-3 w-3 text-success" /></span>
}
