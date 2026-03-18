import { useState, useEffect } from 'react'
import { api } from '@/lib/api'
import type { LogEntry } from '@/lib/api'
import { cn } from '@/lib/utils'
import { RefreshCw } from 'lucide-react'

const levelStyles: Record<string, string> = {
  info: 'text-accent',
  warn: 'text-warning',
  error: 'text-destructive',
}

const levelBg: Record<string, string> = {
  info: 'bg-accent/10',
  warn: 'bg-warning/10',
  error: 'bg-destructive/10',
}

export default function LogsPage() {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [total, setTotal] = useState(0)
  const [level, setLevel] = useState('')
  const [loading, setLoading] = useState(false)
  const [autoRefresh, setAutoRefresh] = useState(true)

  const fetchLogs = () => {
    setLoading(true)
    const params: Record<string, string> = { limit: '500' }
    if (level) params.level = level
    api.getLogs(params)
      .then(data => {
        setLogs(data.logs || [])
        setTotal(data.total || 0)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(() => { fetchLogs() }, [level])

  useEffect(() => {
    if (!autoRefresh) return
    const interval = setInterval(fetchLogs, 3000)
    return () => clearInterval(interval)
  }, [autoRefresh, level])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Application Logs</h1>
        <div className="flex items-center gap-3">
          {/* Level filter */}
          <div className="flex rounded-md border border-border overflow-hidden">
            {['', 'info', 'warn', 'error'].map(l => (
              <button
                key={l}
                onClick={() => setLevel(l)}
                className={cn(
                  'px-3 py-1 text-xs font-medium transition-colors',
                  level === l ? 'bg-accent text-white' : 'text-muted hover:text-foreground'
                )}
              >
                {l || 'All'}
              </button>
            ))}
          </div>

          {/* Auto-refresh toggle */}
          <button
            onClick={() => setAutoRefresh(v => !v)}
            className={cn(
              'flex items-center gap-1.5 rounded-md border px-3 py-1 text-xs font-medium transition-colors',
              autoRefresh ? 'border-accent bg-accent/10 text-accent' : 'border-border text-muted'
            )}
          >
            <RefreshCw className={cn('h-3 w-3', autoRefresh && 'animate-spin')} />
            Live
          </button>

          <span className="text-xs text-muted">{total} total</span>
        </div>
      </div>

      {/* Log entries */}
      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <div className="max-h-[calc(100vh-200px)] overflow-y-auto font-mono text-xs">
          {logs.length === 0 && (
            <div className="text-center py-12 text-muted">
              {loading ? 'Loading...' : 'No log entries'}
            </div>
          )}
          {logs.map((entry, i) => (
            <div
              key={i}
              className={cn(
                'flex items-start gap-3 px-4 py-2 border-b border-border last:border-0 hover:bg-card/80',
                i % 2 === 0 ? 'bg-transparent' : 'bg-background/30'
              )}
            >
              <span className="text-muted shrink-0 w-20">
                {new Date(entry.time).toLocaleTimeString()}
              </span>
              <span className={cn(
                'shrink-0 w-12 text-center rounded px-1 py-0.5 text-[10px] font-bold uppercase',
                levelBg[entry.level] || 'bg-muted/10',
                levelStyles[entry.level] || 'text-muted'
              )}>
                {entry.level}
              </span>
              <span className="text-foreground break-all">{entry.message}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
