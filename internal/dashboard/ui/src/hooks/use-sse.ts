import { useEffect, useRef, useState } from 'react'
import type { WafEvent } from '@/lib/api'

export function useSSE(onEvent: (event: WafEvent) => void) {
  const [connected, setConnected] = useState(false)
  const onEventRef = useRef(onEvent)
  onEventRef.current = onEvent

  useEffect(() => {
    let es: EventSource | null = null
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null
    let backoff = 1000
    let unmounted = false

    function connect() {
      if (unmounted) return

      es = new EventSource('/api/v1/sse')

      es.onopen = () => {
        setConnected(true)
        backoff = 1000
      }

      es.onmessage = (msg) => {
        try {
          const event = JSON.parse(msg.data) as WafEvent
          onEventRef.current(event)
        } catch {
          // ignore malformed messages
        }
      }

      es.onerror = () => {
        setConnected(false)
        es?.close()
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

    return () => {
      unmounted = true
      es?.close()
      if (reconnectTimer) clearTimeout(reconnectTimer)
    }
  }, [])

  return { connected }
}
