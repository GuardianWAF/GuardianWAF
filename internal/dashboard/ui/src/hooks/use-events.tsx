import { createContext, useCallback, useContext, useMemo, useState } from 'react'
import type { WafEvent } from '@/lib/api'

const MAX_EVENTS = 200

export function useEvents() {
  const [events, setEvents] = useState<WafEvent[]>([])
  const [filter, setFilter] = useState('all')
  const [search, setSearch] = useState('')

  const addEvent = useCallback((event: WafEvent) => {
    setEvents((prev) => [event, ...prev].slice(0, MAX_EVENTS))
  }, [])

  const filteredEvents = useMemo(() => {
    let result = events

    if (filter !== 'all') {
      result = result.filter((e) => e.action === filter)
    }

    if (search) {
      const q = search.toLowerCase()
      result = result.filter(
        (e) =>
          (e.client_ip || '').toLowerCase().includes(q) ||
          (e.path || '').toLowerCase().includes(q) ||
          (e.method || '').toLowerCase().includes(q) ||
          (e.browser || '').toLowerCase().includes(q),
      )
    }

    return result
  }, [events, filter, search])

  return {
    events,
    addEvent,
    filter,
    setFilter,
    search,
    setSearch,
    filteredEvents,
  }
}

export const EventsContext = createContext<ReturnType<typeof useEvents> | null>(null)

export function EventsProvider({ children }: { children: React.ReactNode }) {
  const events = useEvents()
  return <EventsContext.Provider value={events}>{children}</EventsContext.Provider>
}

export function useEventsContext() {
  const ctx = useContext(EventsContext)
  if (!ctx) throw new Error('useEventsContext must be used within EventsProvider')
  return ctx
}
