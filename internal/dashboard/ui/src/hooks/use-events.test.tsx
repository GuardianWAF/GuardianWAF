import { describe, it, expect } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useEvents } from './use-events'
import type { WafEvent } from '@/lib/api'

const makeEvent = (overrides: Partial<WafEvent> = {}): WafEvent => ({
  id: '1',
  timestamp: new Date().toISOString(),
  request_id: 'req-1',
  client_ip: '1.2.3.4',
  method: 'GET',
  path: '/test',
  query: '',
  action: 'block',
  score: 80,
  findings: [],
  duration_ns: 1000,
  status_code: 403,
  user_agent: 'test',
  browser: 'Chrome',
  browser_version: '120',
  os: 'Windows',
  device_type: 'desktop',
  is_bot: false,
  ...overrides,
})

describe('useEvents', () => {
  it('starts with empty events', () => {
    const { result } = renderHook(() => useEvents())
    expect(result.current.events).toEqual([])
    expect(result.current.filteredEvents).toEqual([])
  })

  it('adds events', () => {
    const { result } = renderHook(() => useEvents())
    const event = makeEvent()

    act(() => {
      result.current.addEvent(event)
    })

    expect(result.current.events).toHaveLength(1)
    expect(result.current.events[0]).toEqual(event)
  })

  it('limits events to 200', () => {
    const { result } = renderHook(() => useEvents())

    act(() => {
      for (let i = 0; i < 250; i++) {
        result.current.addEvent(makeEvent({ id: String(i) }))
      }
    })

    expect(result.current.events).toHaveLength(200)
    // Most recent first
    expect(result.current.events[0].id).toBe('249')
  })

  it('filters by action', () => {
    const { result } = renderHook(() => useEvents())

    act(() => {
      result.current.addEvent(makeEvent({ action: 'block' }))
      result.current.addEvent(makeEvent({ action: 'pass' }))
      result.current.addEvent(makeEvent({ action: 'block', id: '2' }))
    })

    act(() => {
      result.current.setFilter('block')
    })

    expect(result.current.filteredEvents).toHaveLength(2)
    expect(result.current.filteredEvents.every((e) => e.action === 'block')).toBe(true)
  })

  it('filters by search text', () => {
    const { result } = renderHook(() => useEvents())

    act(() => {
      result.current.addEvent(makeEvent({ client_ip: '10.0.0.1', path: '/api/users' }))
      result.current.addEvent(makeEvent({ client_ip: '192.168.1.1', path: '/login' }))
    })

    act(() => {
      result.current.setSearch('10.0')
    })

    expect(result.current.filteredEvents).toHaveLength(1)
    expect(result.current.filteredEvents[0].client_ip).toBe('10.0.0.1')
  })

  it('combines filter and search', () => {
    const { result } = renderHook(() => useEvents())

    act(() => {
      result.current.addEvent(makeEvent({ action: 'block', client_ip: '10.0.0.1' }))
      result.current.addEvent(makeEvent({ action: 'pass', client_ip: '10.0.0.2' }))
      result.current.addEvent(makeEvent({ action: 'block', client_ip: '192.168.1.1' }))
    })

    act(() => {
      result.current.setFilter('block')
      result.current.setSearch('10.0')
    })

    expect(result.current.filteredEvents).toHaveLength(1)
    expect(result.current.filteredEvents[0].client_ip).toBe('10.0.0.1')
  })

  it('pauses and resumes the feed', () => {
    const { result } = renderHook(() => useEvents())

    // Add an event before pausing
    act(() => {
      result.current.addEvent(makeEvent({ id: 'pre-pause' }))
    })
    expect(result.current.events).toHaveLength(1)

    // Pause the feed
    act(() => {
      result.current.togglePause()
    })
    expect(result.current.paused).toBe(true)

    // Add events while paused — should be buffered, not in the main list
    act(() => {
      result.current.addEvent(makeEvent({ id: 'buffered-1' }))
      result.current.addEvent(makeEvent({ id: 'buffered-2' }))
    })
    expect(result.current.pausedCount).toBe(2)
    expect(result.current.events).toHaveLength(1) // still only the pre-pause event

    // Resume — buffered events should be flushed into the main list
    act(() => {
      result.current.togglePause()
    })
    expect(result.current.paused).toBe(false)
    expect(result.current.pausedCount).toBe(0)
    expect(result.current.events).toHaveLength(3)
    expect(result.current.events[0].id).toBe('buffered-2') // newest first
  })

  it('resets filter to all', () => {
    const { result } = renderHook(() => useEvents())

    act(() => {
      result.current.addEvent(makeEvent({ action: 'block' }))
      result.current.addEvent(makeEvent({ action: 'pass' }))
      result.current.setFilter('block')
    })

    expect(result.current.filteredEvents).toHaveLength(1)

    act(() => {
      result.current.setFilter('all')
    })

    expect(result.current.filteredEvents).toHaveLength(2)
  })
})
