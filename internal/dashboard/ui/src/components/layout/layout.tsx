import { useCallback, useEffect, useState } from 'react'
import { Outlet } from 'react-router'
import { Sidebar } from './sidebar'
import { Header } from './header'
import { useSSE } from '@/hooks/use-sse'
import { EventsProvider, useEventsContext } from '@/hooks/use-events'
import { ToastProvider } from '@/components/ui/toast'

function LayoutInner() {
  const { addEvent, setConnected } = useEventsContext()
  const { connected } = useSSE(addEvent)

  // Sync SSE connection state into the events context so the dashboard page
  // can show the real connection indicator instead of a hardcoded value.
  useEffect(() => {
    setConnected(connected)
  }, [connected, setConnected])

  const [mobileOpen, setMobileOpen] = useState(false)
  const closeMobileSidebar = useCallback(() => setMobileOpen(false), [])
  const openMobileSidebar = useCallback(() => setMobileOpen(true), [])

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar mobileOpen={mobileOpen} onMobileClose={closeMobileSidebar} />
      <div className="flex flex-col flex-1 min-w-0">
        <Header connected={connected} onOpenSidebar={openMobileSidebar} />
        <main className="flex-1 overflow-y-auto p-3 sm:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

export function Layout() {
  return (
    <ToastProvider>
      <EventsProvider>
        <LayoutInner />
      </EventsProvider>
    </ToastProvider>
  )
}
