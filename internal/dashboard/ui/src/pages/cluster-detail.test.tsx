import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router'
import { ErrorBoundary } from '@/components/ui/error-boundary'
import { ToastProvider } from '@/components/ui/toast'
import ClusterDetailPage from './cluster-detail'

// The legacy v0 dashboard endpoints return these shapes — verified against
// internal/dashboard/cluster_handlers.go (handleClusterList /
// handleClusterNodesLegacy). Disabled mode answers wrapper objects with
// message/disabled fields; enabled mode answers {clusters:[{id, role,
// leader_id, peers}]} whose entries carry no name/nodes/sync_scope. The page
// must render against the API the server actually speaks.
vi.mock('@/lib/api', () => ({
  api: {
    getClusters: vi.fn(async () => ({
      clusters: [],
      message: 'cluster mode is not configured',
    })),
    getNodes: vi.fn(async () => ({ nodes: [], disabled: false })),
    joinCluster: vi.fn(),
    leaveCluster: vi.fn(),
  },
}))

function renderDetail(id: string) {
  return render(
    <MemoryRouter initialEntries={[`/clusters/${id}`]}>
      <ToastProvider>
        <ErrorBoundary>
          <Routes>
            <Route path="/clusters/:id" element={<ClusterDetailPage />} />
          </Routes>
        </ErrorBoundary>
      </ToastProvider>
    </MemoryRouter>,
  )
}

// Regression: ClusterDetailPage threw on every data load because it called
// .find/.filter on the wrapper objects the legacy endpoints return instead of
// the arrays the lib/api types promise. Every visit rendered "Cluster not
// found" with a destructive error toast (re-fired by the 10s poll), and the
// enabled-mode branch carried a latent render crash: cluster entries lack the
// nodes field, so cluster.nodes.includes(node.id) would TypeError into the
// error boundary once the .find throw was fixed.
describe('ClusterDetailPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(cleanup)

  it('settles into the not-found state without an error toast (disabled shapes)', async () => {
    renderDetail('does-not-exist')
    expect(await screen.findByText('Cluster not found')).toBeVisible()
    expect(screen.queryByText('Failed to load cluster details')).toBeNull()
    expect(screen.queryByText('Something went wrong')).toBeNull()
  })

  it('renders the detail view against enabled-mode shapes lacking name/nodes', async () => {
    const { api } = await import('@/lib/api')
    vi.mocked(api.getClusters).mockResolvedValue({
      clusters: [{ id: 'node-1', role: 'leader', leader_id: 'node-1', peers: 3 }],
    } as never)
    vi.mocked(api.getNodes).mockResolvedValue({
      nodes: [{ id: 'node-1', role: 'leader', is_leader: true }],
      disabled: false,
    } as never)

    renderDetail('node-1')
    expect(await screen.findByText('ID: node-1')).toBeVisible()
    expect(screen.queryByText('Failed to load cluster details')).toBeNull()
    expect(screen.queryByText('Something went wrong')).toBeNull()
  })
})
