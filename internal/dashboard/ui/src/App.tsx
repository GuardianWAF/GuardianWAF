import { BrowserRouter, Routes, Route } from 'react-router'
import { Layout } from '@/components/layout/layout'
import DashboardPage from '@/pages/dashboard'
import ConfigPage from '@/pages/config'
import RoutingPage from '@/pages/routing'
import LogsPage from '@/pages/logs'

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<DashboardPage />} />
          <Route path="/config" element={<ConfigPage />} />
          <Route path="/routing" element={<RoutingPage />} />
          <Route path="/logs" element={<LogsPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
