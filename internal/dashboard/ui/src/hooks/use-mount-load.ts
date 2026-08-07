import { useEffect } from 'react'

/**
 * Runs an async loader once per `load` identity, without writing state
 * synchronously while the effect is executing.
 *
 * Fetch-on-mount loaders typically start with `setLoading(true)`. Calling such
 * a loader directly from `useEffect` writes state during the effect, which
 * costs an extra cascading render pass and is reported by
 * `react-hooks/set-state-in-effect`. Yielding to a microtask first moves every
 * state write out of the synchronous effect body.
 *
 * The loader receives an `isCancelled` probe so it can skip state updates once
 * the component has unmounted, which also removes the unmounted-setState race
 * these pages previously had.
 */
export function useMountLoad(load: (isCancelled: () => boolean) => void | Promise<void>) {
  useEffect(() => {
    let cancelled = false
    const isCancelled = () => cancelled
    void (async () => {
      await Promise.resolve()
      if (!cancelled) await load(isCancelled)
    })()
    return () => {
      cancelled = true
    }
  }, [load])
}

/**
 * `useMountLoad` plus a refresh timer.
 *
 * Loads once on mount, then re-runs `load` every `intervalMs`. Set `enabled` to
 * false to skip both (for example while a route parameter is still undefined);
 * the timer is cleared and further state writes suppressed on unmount.
 */
export function usePollingLoad(
  load: (isCancelled: () => boolean) => void | Promise<void>,
  intervalMs: number,
  enabled = true,
) {
  useEffect(() => {
    if (!enabled) return
    let cancelled = false
    const isCancelled = () => cancelled
    void (async () => {
      await Promise.resolve()
      if (!cancelled) await load(isCancelled)
    })()
    const timer = setInterval(() => {
      void load(isCancelled)
    }, intervalMs)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [load, intervalMs, enabled])
}
