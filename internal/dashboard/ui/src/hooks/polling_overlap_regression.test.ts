import { act, renderHook } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { usePollingLoad } from './use-mount-load'

afterEach(() => { vi.useRealTimers() })
function deferred() {
  let resolve!: () => void
  const promise = new Promise<void>(done => { resolve = done })
  return { promise, resolve }
}
it('F153 serializes polls and resumes after completion', async () => {
  vi.useFakeTimers()
  const gate = deferred()
  let calls = 0
  const published: number[] = []
  const load = async (isCancelled: () => boolean) => {
    const id = ++calls
    if (id === 1) await gate.promise
    if (!isCancelled()) published.push(id)
  }
  const hook = renderHook(() => usePollingLoad(load, 10))
  await act(async () => { await Promise.resolve() })
  await act(async () => { vi.advanceTimersByTime(50); await Promise.resolve() })
  expect(calls).toBe(1)
  expect(published).toEqual([])
  await act(async () => { gate.resolve(); await gate.promise })
  await act(async () => { vi.advanceTimersByTime(10); await Promise.resolve() })
  expect(published).toEqual([1, 2])
  expect(calls).toBe(2)
  hook.unmount()
  expect(vi.getTimerCount()).toBe(0)
})
it('F153 suppresses pending publication after unmount', async () => {
  vi.useFakeTimers()
  const gate = deferred()
  const published = vi.fn()
  const load = async (isCancelled: () => boolean) => {
    await gate.promise
    if (!isCancelled()) published()
  }
  const hook = renderHook(() => usePollingLoad(load, 10))
  await act(async () => { await Promise.resolve() })
  hook.unmount()
  await act(async () => { gate.resolve(); await gate.promise })
  expect(published).not.toHaveBeenCalled()
  expect(vi.getTimerCount()).toBe(0)
})
it('F153 cancels the old loader when identity changes and supports disabled polling', async () => {
  vi.useFakeTimers()
  const gate = deferred()
  const published: string[] = []
  const old = async (isCancelled: () => boolean) => {
    await gate.promise
    if (!isCancelled()) published.push('old')
  }
  const next = vi.fn((isCancelled: () => boolean) => {
    if (!isCancelled()) published.push('new')
  })
  const hook = renderHook(({ load, enabled }) => usePollingLoad(load, 10, enabled), {
    initialProps: { load: old as (isCancelled: () => boolean) => void | Promise<void>, enabled: true },
  })
  await act(async () => { await Promise.resolve() })
  hook.rerender({ load: next, enabled: true })
  await act(async () => { await Promise.resolve() })
  await act(async () => { gate.resolve(); await gate.promise })
  expect(published).toEqual(['new'])
  hook.rerender({ load: next, enabled: false })
  await act(async () => { vi.advanceTimersByTime(100); await Promise.resolve() })
  expect(next).toHaveBeenCalledTimes(1)
  expect(vi.getTimerCount()).toBe(0)
  hook.unmount()
})
