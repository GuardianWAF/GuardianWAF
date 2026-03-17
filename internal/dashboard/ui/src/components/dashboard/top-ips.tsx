import { Globe } from 'lucide-react'
import type { WafEvent } from '@/lib/api'

interface TopIPsProps {
  events: WafEvent[]
}

export function TopIPs({ events }: TopIPsProps) {
  // Count IPs from events
  const ipCounts = new Map<string, { total: number; blocked: number }>()
  for (const e of events) {
    if (!e.client_ip) continue
    const entry = ipCounts.get(e.client_ip) || { total: 0, blocked: 0 }
    entry.total++
    if (e.action === 'block') entry.blocked++
    ipCounts.set(e.client_ip, entry)
  }

  const sorted = Array.from(ipCounts.entries())
    .sort((a, b) => b[1].total - a[1].total)
    .slice(0, 10)

  if (sorted.length === 0) return null

  const maxCount = sorted[0]?.[1].total || 1

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
        <Globe className="h-4 w-4 text-muted" />
        <h3 className="text-sm font-semibold">Top Source IPs</h3>
      </div>
      <div className="p-4 space-y-2">
        {sorted.map(([ip, counts]) => (
          <div key={ip} className="flex items-center gap-3">
            <span className="text-xs font-mono w-32 shrink-0">{ip}</span>
            <div className="flex-1 h-5 bg-background rounded overflow-hidden">
              <div
                className="h-full bg-accent/30 rounded transition-all"
                style={{ width: `${(counts.total / maxCount) * 100}%` }}
              />
            </div>
            <span className="text-xs text-muted w-10 text-right">{counts.total}</span>
            {counts.blocked > 0 && (
              <span className="text-[10px] text-destructive w-10 text-right">{counts.blocked} blk</span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
