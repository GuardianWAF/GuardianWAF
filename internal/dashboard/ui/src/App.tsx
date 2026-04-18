import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router'
import { ErrorBoundary } from '@/components/ui/error-boundary'
import { Layout } from '@/components/layout/layout'

const DashboardPage = lazy(() => import('@/pages/dashboard'))
const ConfigPage = lazy(() => import('@/pages/config'))
const RoutingPage = lazy(() => import('@/pages/routing'))
const LogsPage = lazy(() => import('@/pages/logs'))
const RulesPage = lazy(() => import('@/pages/rules'))
const AIPage = lazy(() => import('@/pages/ai'))
const AlertingPage = lazy(() => import('@/pages/alerting'))
const TenantsPage = lazy(() => import('@/pages/tenants'))
const TenantNewPage = lazy(() => import('@/pages/tenant-new'))
const TenantDetailPage = lazy(() => import('@/pages/tenant-detail'))
const TenantAnalyticsPage = lazy(() => import('@/pages/tenant-analytics'))
const ClustersPage = lazy(() => import('@/pages/clusters'))
const ClusterDetailPage = lazy(() => import('@/pages/cluster-detail'))
const SSLPage = lazy(() => import('@/pages/ssl'))
const CompliancePage = lazy(() => import('@/pages/compliance'))

function PageLoader() {
  return (
    <div className="flex min-h-[50vh] items-center justify-center">
      <div className="h-6 w-6 animate-spin rounded-full border-2 border-accent border-t-transparent" />
    </div>
  )
}

export function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Suspense fallback={<PageLoader />}><DashboardPage /></Suspense>} />
            <Route path="/routing" element={<Suspense fallback={<PageLoader />}><RoutingPage /></Suspense>} />
            <Route path="/rules" element={<Suspense fallback={<PageLoader />}><RulesPage /></Suspense>} />
            <Route path="/config" element={<Suspense fallback={<PageLoader />}><ConfigPage /></Suspense>} />
            <Route path="/alerting" element={<Suspense fallback={<PageLoader />}><AlertingPage /></Suspense>} />
            <Route path="/ssl" element={<Suspense fallback={<PageLoader />}><SSLPage /></Suspense>} />
            <Route path="/ai" element={<Suspense fallback={<PageLoader />}><AIPage /></Suspense>} />
            <Route path="/compliance" element={<Suspense fallback={<PageLoader />}><CompliancePage /></Suspense>} />
            <Route path="/logs" element={<Suspense fallback={<PageLoader />}><LogsPage /></Suspense>} />
            <Route path="/tenants" element={<Suspense fallback={<PageLoader />}><TenantsPage /></Suspense>} />
            <Route path="/tenants/new" element={<Suspense fallback={<PageLoader />}><TenantNewPage /></Suspense>} />
            <Route path="/tenants/:id" element={<Suspense fallback={<PageLoader />}><TenantDetailPage /></Suspense>} />
            <Route path="/tenants/:id/analytics" element={<Suspense fallback={<PageLoader />}><TenantAnalyticsPage /></Suspense>} />
            <Route path="/clusters" element={<Suspense fallback={<PageLoader />}><ClustersPage /></Suspense>} />
            <Route path="/clusters/:id" element={<Suspense fallback={<PageLoader />}><ClusterDetailPage /></Suspense>} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  )
}
