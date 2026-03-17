import { useState } from 'react'
import { cn, timeAgo } from '@/lib/utils'
import type { WafEvent } from '@/lib/api'
import { EventDetail } from './event-detail'

interface EventsTableProps {
  events: WafEvent[]
  filter: string
  setFilter: (f: string) => void
  search: string
  setSearch: (s: string) => void
}

const filters = [
  { value: 'all', label: 'All' },
  { value: 'block', label: 'Blocked', color: 'text-destructive' },
  { value: 'challenge', label: 'Challenged', color: 'text-orange' },
  { value: 'log', label: 'Logged', color: 'text-warning' },
  { value: 'pass', label: 'Passed', color: 'text-success' },
]

const actionStyles: Record<string, string> = {
  block: 'bg-destructive/15 text-destructive',
  challenge: 'bg-orange/15 text-orange',
  log: 'bg-warning/15 text-warning',
  pass: 'bg-success/15 text-success',
}

export function EventsTable({ events, filter, setFilter, search, setSearch }: EventsTableProps) {
  const [selectedEvent, setSelectedEvent] = useState<WafEvent | null>(null)

  const filtered = events.filter(e => {
    if (filter !== 'all' && e.action !== filter) return false
    if (search) {
      const q = search.toLowerCase()
      const haystack = [e.client_ip, e.method, e.path, e.action, e.browser, e.os, e.device_type].join(' ').toLowerCase()
      if (!haystack.includes(q)) return false
    }
    return true
  })

  return (
    <>
      <div className="rounded-lg border border-border bg-card">
        {/* Header */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 px-4 py-3 border-b border-border">
          <h3 className="text-sm font-semibold">Live Event Feed</h3>
          <div className="flex items-center gap-2 flex-wrap">
            <div className="flex rounded-md border border-border overflow-hidden">
              {filters.map(f => (
                <button
                  key={f.value}
                  onClick={() => setFilter(f.value)}
                  className={cn(
                    'px-3 py-1 text-xs font-medium transition-colors',
                    filter === f.value
                      ? 'bg-accent text-accent-foreground'
                      : 'text-muted hover:bg-card hover:text-foreground'
                  )}
                >
                  {f.label}
                </button>
              ))}
            </div>
            <input
              type="text"
              placeholder="Search..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="h-7 rounded-md border border-border bg-background px-2.5 text-xs text-foreground placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-accent w-40"
            />
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border text-muted">
                <th className="text-left px-3 py-2 font-medium">Time</th>
                <th className="text-left px-3 py-2 font-medium">IP</th>
                <th className="text-left px-3 py-2 font-medium">Method</th>
                <th className="text-left px-3 py-2 font-medium">Path</th>
                <th className="text-left px-3 py-2 font-medium">Action</th>
                <th className="text-left px-3 py-2 font-medium">Score</th>
                <th className="text-left px-3 py-2 font-medium hidden lg:table-cell">Browser</th>
                <th className="text-left px-3 py-2 font-medium hidden lg:table-cell">Device</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={8} className="text-center py-8 text-muted">
                    {events.length === 0 ? 'Waiting for events...' : 'No events match filter'}
                  </td>
                </tr>
              )}
              {filtered.slice(0, 100).map(event => (
                <tr
                  key={event.id}
                  onClick={() => setSelectedEvent(event)}
                  className="border-b border-border hover:bg-card cursor-pointer transition-colors"
                >
                  <td className="px-3 py-2 text-muted whitespace-nowrap" title={event.timestamp}>
                    {timeAgo(event.timestamp)}
                  </td>
                  <td className="px-3 py-2 font-mono">{event.client_ip}</td>
                  <td className="px-3 py-2">
                    <span className="font-mono font-medium">{event.method}</span>
                  </td>
                  <td className="px-3 py-2 font-mono max-w-[200px] truncate" title={event.path}>
                    {event.path}
                  </td>
                  <td className="px-3 py-2">
                    <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase', actionStyles[event.action] || 'bg-muted/20 text-muted')}>
                      {event.action}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <span className={cn('font-mono font-bold', event.score >= 50 ? 'text-destructive' : event.score >= 25 ? 'text-warning' : 'text-muted')}>
                      {event.score}
                    </span>
                  </td>
                  <td className="px-3 py-2 hidden lg:table-cell text-muted">
                    {event.browser}{event.browser_version ? ' ' + event.browser_version : ''}
                  </td>
                  <td className="px-3 py-2 hidden lg:table-cell">
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted/10 text-muted">
                      {event.device_type || 'unknown'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        <div className="px-4 py-2 border-t border-border text-xs text-muted">
          {filtered.length} events{filter !== 'all' ? ` (filtered from ${events.length})` : ''}
        </div>
      </div>

      {/* Event Detail Sheet */}
      {selectedEvent && (
        <EventDetail event={selectedEvent} onClose={() => setSelectedEvent(null)} />
      )}
    </>
  )
}
