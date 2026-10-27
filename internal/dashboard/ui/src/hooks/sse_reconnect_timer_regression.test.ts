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
beforeEach(() => { FakeSource.instances=[]; vi.useFakeTimers(); vi.stubGlobal('EventSource',FakeSource); vi.spyOn(document,'hidden','get').mockReturnValue(false) })
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers() })
it('F144 visibility recovery cancels a pending retry', () => {
  const { unmount } = renderHook(() => useSSE(vi.fn()))
  act(() => FakeSource.instances[0].onerror?.())
  act(() => vi.advanceTimersByTime(1000))
  expect(FakeSource.instances.length).toBe(2)
  console.log('CONTROL: ordinary retry creates exactly one replacement')
  act(() => FakeSource.instances[1].onerror?.())
  act(() => document.dispatchEvent(new Event('visibilitychange')))
  expect(FakeSource.instances.length).toBe(3)
  act(() => vi.advanceTimersByTime(2000))
  const got=FakeSource.instances.length
  unmount()
  console.log(`EXPECTED: sources=3; ACTUAL: sources=${got}`)
  if(got!==3) throw new Error('PROBLEM CONFIRMED')
  console.log('FIX VERIFIED')
})

it('F144 repeated visibility events keep only one source', () => {
  const {unmount}=renderHook(()=>useSSE(vi.fn()))
  act(()=>FakeSource.instances[0].onerror?.())
  act(()=>{document.dispatchEvent(new Event('visibilitychange'));document.dispatchEvent(new Event('visibilitychange'))})
  act(()=>vi.advanceTimersByTime(30000))
  expect(FakeSource.instances).toHaveLength(2)
  unmount()
  expect(FakeSource.instances[1].close).toHaveBeenCalledTimes(1)
})
it('F144 unmount cancels a retry at its boundary', () => {
  const {unmount}=renderHook(()=>useSSE(vi.fn()))
  act(()=>FakeSource.instances[0].onerror?.())
  act(()=>vi.advanceTimersByTime(999))
  unmount()
  act(()=>vi.advanceTimersByTime(1))
  expect(FakeSource.instances).toHaveLength(1)
  expect(vi.getTimerCount()).toBe(0)
})
