import { Outlet } from 'react-router'
import { Sidebar } from './sidebar'
import { Header } from './header'
import { useSSE } from '@/hooks/use-sse'
import { EventsProvider, useEventsContext } from '@/hooks/use-events'
import { ToastProvider } from '@/components/ui/toast'

function LayoutInner() {
  const { addEvent } = useEventsContext()
  const { connected } = useSSE(addEvent)

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0">
        <Header connected={connected} />
        <main className="flex-1 overflow-y-auto p-6">
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
