import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react'
import type { WafEvent } from '@/lib/api'

const MAX_EVENTS = 200

export function useEvents() {
  const [events, setEvents] = useState<WafEvent[]>([])
  const [filter, setFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [paused, setPaused] = useState(false)
  const [connected, setConnected] = useState(false)
  const [pausedCount, setPausedCount] = useState(0)
  const pendingRef = useRef<WafEvent[]>([])

  const addEvent = useCallback((event: WafEvent) => {
    if (paused) {
      pendingRef.current.push(event)
      if (pendingRef.current.length > MAX_EVENTS) {
        pendingRef.current = pendingRef.current.slice(-MAX_EVENTS)
      }
      setPausedCount(pendingRef.current.length)
      return
    }
    setEvents((prev) => [event, ...prev].slice(0, MAX_EVENTS))
  }, [paused])

  const resume = useCallback(() => {
    if (pendingRef.current.length > 0) {
      const buffered = [...pendingRef.current].reverse()
      pendingRef.current = []
      setEvents((prev) => [...buffered, ...prev].slice(0, MAX_EVENTS))
    }
    setPaused(false)
    setPausedCount(0)
  }, [])

  const pause = useCallback(() => {
    setPaused(true)
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

  const togglePause = useCallback(() => {
    if (paused) {
      resume()
    } else {
      pause()
    }
  }, [paused, pause, resume])

  return {
    events,
    addEvent,
    filter,
    setFilter,
    search,
    setSearch,
    filteredEvents,
    paused,
    pausedCount,
    togglePause,
    sseConnected: connected,
    setConnected,
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
