import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { ErrorBoundary } from '@/components/ui/error-boundary'
import { ToastProvider } from '@/components/ui/toast'
import ClustersPage from './clusters'

// The legacy v0 dashboard endpoints return these shapes when cluster sync is
// not configured — verified against internal/dashboard/cluster_handlers.go
// (handleClusterList / handleClusterNodesLegacy / handleSyncStats /
// handleSyncStatus, the clusterStatus == nil branches). The page must render
// against the API the server actually speaks, not against the TS interfaces.
vi.mock('@/lib/api', () => ({
  api: {
    getClusters: vi.fn(async () => ({
      clusters: [],
      message: 'cluster mode is not configured',
    })),
    getNodes: vi.fn(async () => ({ nodes: [], disabled: false })),
    getSyncStats: vi.fn(async () => ({
      enabled: false,
      message: 'cluster sync is not configured',
    })),
    getSyncStatus: vi.fn(async () => ({
      enabled: false,
      syncing: false,
      message: 'cluster sync is not configured',
    })),
    deleteCluster: vi.fn(),
  },
}))

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/clusters']}>
      <ToastProvider>
        <ErrorBoundary>
          <ClustersPage />
        </ErrorBoundary>
      </ToastProvider>
    </MemoryRouter>,
  )
}

// Regression: ClustersPage crashed into the error boundary on every data load
// because it assumed response shapes (Cluster[], SyncStats.total_events_*,
// SyncStatusResponse.nodes) the legacy endpoints never return. The dashboard
// e2e suite pinned this as a deterministic failure: the "Cluster Sync" heading
// was replaced by the boundary's "Something went wrong".
describe('ClustersPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(cleanup)

  it('renders the heading against the legacy cluster-sync API shapes', async () => {
    renderPage()
    expect(await screen.findByRole('heading', { name: 'Cluster Sync' })).toBeVisible()
    expect(screen.queryByText('Something went wrong')).toBeNull()
  })

  it('renders node replication status when sync status carries a nodes array', async () => {
    const { api } = await import('@/lib/api')
    vi.mocked(api.getSyncStatus).mockResolvedValue({
      local_node: 'node-1',
      nodes: [
        {
          node_id: 'node-1',
          last_replication: '2026-09-13T00:00:00Z',
          lag_ms: 1200,
          pending_events: 0,
          failed_attempts: 0,
        },
      ],
    } as never)

    renderPage()
    expect(await screen.findByRole('heading', { name: 'Cluster Sync' })).toBeVisible()
    expect(await screen.findByText('Node Replication Status')).toBeVisible()
    expect(screen.queryByText('Something went wrong')).toBeNull()
  })
})
