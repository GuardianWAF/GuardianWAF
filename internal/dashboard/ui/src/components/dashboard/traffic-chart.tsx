import { useMemo, memo } from 'react'
import { cn } from '@/lib/utils'
import type { WafEvent } from '@/lib/api'
import { Activity } from 'lucide-react'

interface TrafficChartProps {
  events: WafEvent[]
  minutes?: number
}

interface Bucket {
  time: string
  total: number
  blocked: number
  challenged: number
  logged: number
  passed: number
}

export const TrafficChart = memo(function TrafficChart({ events, minutes = 30 }: TrafficChartProps) {
  const buckets = useMemo(() => {
    const now = Date.now()
    const bucketSize = 60_000 // 1 minute
    const count = minutes
    const result: Bucket[] = []

    // Initialize empty buckets
    for (let i = count - 1; i >= 0; i--) {
      const t = now - i * bucketSize
      const d = new Date(t)
      result.push({
        time: d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0'),
        total: 0, blocked: 0, challenged: 0, logged: 0, passed: 0,
      })
    }

    // Fill from events
    for (const e of events) {
      const ts = new Date(e.timestamp).getTime()
      const age = now - ts
      if (age < 0 || age > count * bucketSize) continue
      const idx = count - 1 - Math.floor(age / bucketSize)
      if (idx >= 0 && idx < count) {
        result[idx].total++
        if (e.action === 'block') result[idx].blocked++
        else if (e.action === 'challenge') result[idx].challenged++
        else if (e.action === 'log') result[idx].logged++
        else result[idx].passed++
      }
    }

    return result
  }, [events, minutes])

  const maxVal = Math.max(1, ...buckets.map(b => b.total))

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <div className="flex items-center gap-2">
          <Activity className="h-4 w-4 text-muted" />
          <h3 className="text-sm font-semibold">Traffic (Last {minutes}m)</h3>
        </div>
        <div className="flex items-center gap-3 text-[10px]">
          <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-success" /> Passed</span>
          <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-warning" /> Logged</span>
          <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-orange" /> Challenged</span>
          <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-destructive" /> Blocked</span>
        </div>
      </div>

      <div className="px-4 py-3" role="img" aria-label={`Traffic chart for last ${minutes} minutes: ${buckets[buckets.length - 1]?.total || 0} current requests per minute`}>
        <div className="flex items-end gap-[2px] h-32">
          {buckets.map((b, i) => {
            const totalH = (b.total / maxVal) * 100
            const blockedH = b.total > 0 ? (b.blocked / b.total) * totalH : 0
            const challengedH = b.total > 0 ? (b.challenged / b.total) * totalH : 0
            const loggedH = b.total > 0 ? (b.logged / b.total) * totalH : 0
            const passedH = totalH - blockedH - challengedH - loggedH

            return (
              <div
                key={i}
                className="flex-1 flex flex-col justify-end group relative"
                title={`${b.time} — ${b.total} req (${b.blocked} blocked, ${b.challenged} challenged, ${b.logged} logged, ${b.passed} passed)`}
              >
                {/* Stacked bar */}
                <div className="w-full flex flex-col justify-end" style={{ height: `${totalH}%`, minHeight: b.total > 0 ? '2px' : 0 }}>
                  {passedH > 0 && <div className="w-full bg-success/60 rounded-t-[1px]" style={{ height: `${passedH}%`, minHeight: '1px' }} />}
                  {loggedH > 0 && <div className="w-full bg-warning/70" style={{ height: `${loggedH}%`, minHeight: '1px' }} />}
                  {challengedH > 0 && <div className="w-full bg-orange/70" style={{ height: `${challengedH}%`, minHeight: '1px' }} />}
                  {blockedH > 0 && <div className="w-full bg-destructive/80 rounded-b-[1px]" style={{ height: `${blockedH}%`, minHeight: '1px' }} />}
                </div>

                {/* Hover tooltip */}
                <div className={cn(
                  'absolute bottom-full mb-2 left-1/2 -translate-x-1/2 hidden group-hover:block z-10',
                  'bg-card border border-border rounded-md shadow-lg px-2 py-1.5 text-[10px] whitespace-nowrap'
                )}>
                  <div className="font-bold">{b.time}</div>
                  <div>{b.total} requests</div>
                  {b.blocked > 0 && <div className="text-destructive">{b.blocked} blocked</div>}
                  {b.challenged > 0 && <div className="text-orange">{b.challenged} challenged</div>}
                  {b.logged > 0 && <div className="text-warning">{b.logged} logged</div>}
                </div>
              </div>
            )
          })}
        </div>

        {/* Time labels */}
        <div className="flex justify-between mt-1 text-[9px] text-muted">
          <span>{buckets[0]?.time}</span>
          <span>{buckets[Math.floor(buckets.length / 2)]?.time}</span>
          <span>{buckets[buckets.length - 1]?.time}</span>
        </div>
      </div>
    </div>
  )
})
