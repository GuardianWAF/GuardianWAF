import { useEffect, useRef, useState } from 'react'
import type { WafEvent } from '@/lib/api'

export function useSSE(onEvent: (event: WafEvent) => void) {
  const [connected, setConnected] = useState(false)
  const onEventRef = useRef(onEvent)
  // eslint-disable-next-line react-hooks/refs
  onEventRef.current = onEvent

  useEffect(() => {
    let es: EventSource | null = null
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null
    let backoff = 1000
    let unmounted = false

    function connect() {
      if (unmounted) return
      if (reconnectTimer !== null) {
        clearTimeout(reconnectTimer)
        reconnectTimer = null
      }

      const source = new EventSource('/api/v1/sse')
      es = source

      source.onopen = () => {
        if (unmounted || es !== source) return
        setConnected(true)
        backoff = 1000
      }

      source.onmessage = (msg) => {
        if (unmounted || es !== source) return
        try {
          const data = JSON.parse(msg.data)
          // Only forward actual WAF events (not control messages like {"type":"connected"})
          if (data.action && data.client_ip) {
            onEventRef.current(data as WafEvent)
          }
        } catch {
          // ignore malformed messages
        }
      }

      source.onerror = () => {
        if (unmounted || es !== source) return
        setConnected(false)
        source.close()
        es = null

        if (!unmounted) {
          reconnectTimer = setTimeout(() => {
            backoff = Math.min(backoff * 2, 30_000)
            connect()
          }, backoff)
        }
      }
    }

    connect()

    // Reconnect when tab becomes visible after being hidden
    function onVisibilityChange() {
      if (!document.hidden && !es && !unmounted) {
        backoff = 1000
        connect()
      }
    }
    document.addEventListener('visibilitychange', onVisibilityChange)

    return () => {
      unmounted = true
      es?.close()
      if (reconnectTimer) clearTimeout(reconnectTimer)
      document.removeEventListener('visibilitychange', onVisibilityChange)
    }
  }, [])

  return { connected }
}
