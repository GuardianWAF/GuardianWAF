import { BrowserRouter, Routes, Route } from 'react-router'
import { Layout } from '@/components/layout/layout'
import DashboardPage from '@/pages/dashboard'
import ConfigPage from '@/pages/config'
import RoutingPage from '@/pages/routing'
import LogsPage from '@/pages/logs'
import RulesPage from '@/pages/rules'
import AIPage from '@/pages/ai'
import AlertingPage from '@/pages/alerting'
import TenantsPage from '@/pages/tenants'
import TenantNewPage from '@/pages/tenant-new'
import TenantDetailPage from '@/pages/tenant-detail'
import TenantAnalyticsPage from '@/pages/tenant-analytics'
import ClustersPage from '@/pages/clusters'
import ClusterDetailPage from '@/pages/cluster-detail'

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<DashboardPage />} />
          <Route path="/routing" element={<RoutingPage />} />
          <Route path="/rules" element={<RulesPage />} />
          <Route path="/config" element={<ConfigPage />} />
          <Route path="/alerting" element={<AlertingPage />} />
          <Route path="/ai" element={<AIPage />} />
          <Route path="/logs" element={<LogsPage />} />
          <Route path="/tenants" element={<TenantsPage />} />
          <Route path="/tenants/new" element={<TenantNewPage />} />
          <Route path="/tenants/:id" element={<TenantDetailPage />} />
          <Route path="/tenants/:id/analytics" element={<TenantAnalyticsPage />} />
          <Route path="/clusters" element={<ClustersPage />} />
          <Route path="/clusters/:id" element={<ClusterDetailPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
