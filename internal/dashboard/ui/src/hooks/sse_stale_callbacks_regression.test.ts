import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { useSSE } from './use-sse'

class FakeSource {
  static instances: FakeSource[] = []
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  onmessage: ((message: MessageEvent) => void) | null = null
  close = vi.fn()
  constructor() { FakeSource.instances.push(this) }
}
beforeEach(() => { FakeSource.instances = []; vi.stubGlobal('EventSource', FakeSource) })
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers() })
const message = { data: JSON.stringify({ action: 'pass', client_ip: '192.0.2.1' }) } as MessageEvent
it('F143 blocks a queued callback after unmount', async () => {
  const onEvent = vi.fn()
  const { unmount } = renderHook(() => useSSE(onEvent))
  const source = FakeSource.instances[0]
  act(() => source.onmessage?.(message))
  expect(onEvent).toHaveBeenCalledTimes(1)
  console.log('CONTROL: mounted event delivered once')
  onEvent.mockClear()
  let release!: () => void
  const gate = new Promise<void>(resolve => { release = resolve })
  const queued = gate.then(() => source.onmessage?.(message))
  unmount()
  await act(async () => { release(); await queued })
  console.log(`EXPECTED: callbacks=0; ACTUAL: callbacks=${onEvent.mock.calls.length}`)
  if (onEvent.mock.calls.length !== 0) throw new Error('PROBLEM CONFIRMED')
  console.log('FIX VERIFIED')
})

it('F143 ignores callbacks from a replaced source', async () => {
  vi.useFakeTimers()
  const onEvent=vi.fn()
  const { result,unmount }=renderHook(()=>useSSE(onEvent))
  const old=FakeSource.instances[0]
  act(()=>old.onerror?.())
  act(()=>vi.advanceTimersByTime(1000))
  const current=FakeSource.instances[1]
  act(()=>current.onopen?.())
  expect(result.current.connected).toBe(true)
  let release!:()=>void
  const gate=new Promise<void>(resolve=>{release=resolve})
  const stale=gate.then(()=>{old.onmessage?.(message);old.onerror?.()})
  await act(async()=>{release();await stale})
  expect(onEvent).not.toHaveBeenCalled()
  expect(current.close).not.toHaveBeenCalled()
  expect(result.current.connected).toBe(true)
  unmount()
})
it('F143 late errors after unmount never schedule retries', () => {
  vi.useFakeTimers()
  const {unmount}=renderHook(()=>useSSE(vi.fn()))
  const source=FakeSource.instances[0]
  unmount()
  act(()=>{source.onopen?.();source.onerror?.();vi.advanceTimersByTime(30000)})
  expect(FakeSource.instances).toHaveLength(1)
  expect(vi.getTimerCount()).toBe(0)
})
