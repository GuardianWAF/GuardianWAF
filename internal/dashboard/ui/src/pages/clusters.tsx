import { useState, useEffect } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { useToast } from '@/components/ui/toast'
import { api, Cluster, SyncStats, SyncStatusResponse } from '@/lib/api'
import { Plus, Search, Trash2, RefreshCw, Server, Activity, ArrowRight } from 'lucide-react'

export default function ClustersPage() {
  const [clusters, setClusters] = useState<Cluster[]>([])
  const [nodes, setNodes] = useState<Record<string, { healthy?: boolean; last_seen?: string }>>({})
  const [syncStats, setSyncStats] = useState<SyncStats | null>(null)
  const [syncStatus, setSyncStatus] = useState<SyncStatusResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const { toast } = useToast()

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 10000) // Refresh every 10s
    return () => clearInterval(interval)
  }, [])

  const loadData = async () => {
    try {
      const [clustersData, nodesData, statsData, statusData] = await Promise.all([
        api.getClusters(),
        api.getNodes(),
        api.getSyncStats(),
        api.getSyncStatus()
      ])
      setClusters(clustersData)
      setSyncStats(statsData)
      setSyncStatus(statusData)

      // Create nodes lookup map
      const nodesMap: Record<string, { healthy?: boolean; last_seen?: string }> = {}
      nodesData.forEach(node => {
        nodesMap[node.id] = { healthy: node.healthy, last_seen: node.last_seen }
      })
      setNodes(nodesMap)
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to load cluster data',
        variant: 'destructive'
      })
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this cluster?')) return

    try {
      await api.deleteCluster(id)
      toast({ title: 'Success', description: 'Cluster deleted' })
      loadData()
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to delete cluster',
        variant: 'destructive'
      })
    }
  }

  const handleRefresh = () => {
    setLoading(true)
    loadData()
  }

  const filteredClusters = clusters.filter(c =>
    c.name.toLowerCase().includes(search.toLowerCase()) ||
    c.id.toLowerCase().includes(search.toLowerCase())
  )

  const getScopeColor = (scope: string) => {
    switch (scope) {
      case 'all': return 'bg-green-500'
      case 'tenants': return 'bg-blue-500'
      case 'rules': return 'bg-purple-500'
      case 'config': return 'bg-orange-500'
      default: return 'bg-gray-500'
    }
  }

  const getNodeHealth = (nodeIds: string[]) => {
    if (nodeIds.length === 0) return { healthy: 0, total: 0 }
    const healthy = nodeIds.filter(id => nodes[id]?.healthy).length
    return { healthy, total: nodeIds.length }
  }

  const formatNumber = (num: number) => {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
    return num.toString()
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Cluster Sync</h1>
        <div className="flex gap-2">
          <Button variant="outline" onClick={handleRefresh}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button onClick={() => window.location.href = '/clusters/new'}>
            <Plus className="w-4 h-4 mr-2" />
            New Cluster
          </Button>
        </div>
      </div>

      {/* Sync Stats Cards */}
      {syncStats && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <Activity className="w-5 h-5 text-blue-500" />
                <div>
                  <div className="text-2xl font-bold">{formatNumber(syncStats.total_events_sent)}</div>
                  <div className="text-sm text-gray-500">Events Sent</div>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <Server className="w-5 h-5 text-green-500" />
                <div>
                  <div className="text-2xl font-bold">{formatNumber(syncStats.total_events_received)}</div>
                  <div className="text-sm text-gray-500">Events Received</div>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <Activity className="w-5 h-5 text-orange-500" />
                <div>
                  <div className="text-2xl font-bold">{syncStats.total_conflicts}</div>
                  <div className="text-sm text-gray-500">Conflicts</div>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <Server className="w-5 h-5 text-purple-500" />
                <div>
                  <div className="text-2xl font-bold">{syncStats.active_connections}</div>
                  <div className="text-sm text-gray-500">Active Connections</div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Clusters Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <Input
                placeholder="Search clusters..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-10"
              />
            </div>
            <div className="text-sm text-gray-500">
              {clusters.length} clusters
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="text-center py-8">Loading...</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700">
                    <th className="text-left py-3 px-4 font-medium">Cluster</th>
                    <th className="text-left py-3 px-4 font-medium">Sync Scope</th>
                    <th className="text-left py-3 px-4 font-medium">Nodes</th>
                    <th className="text-left py-3 px-4 font-medium">Health</th>
                    <th className="text-left py-3 px-4 font-medium">Created</th>
                    <th className="text-left py-3 px-4 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredClusters.map((cluster) => {
                    const health = getNodeHealth(cluster.nodes)
                    return (
                      <tr
                        key={cluster.id}
                        className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer"
                        onClick={() => window.location.href = `/clusters/${cluster.id}`}
                      >
                        <td className="py-3 px-4">
                          <div>
                            <div className="font-medium">{cluster.name}</div>
                            <div className="text-xs text-gray-400">ID: {cluster.id}</div>
                            {cluster.description && (
                              <div className="text-sm text-gray-500">{cluster.description}</div>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <Badge className={getScopeColor(cluster.sync_scope)}>
                            {cluster.sync_scope}
                          </Badge>
                        </td>
                        <td className="py-3 px-4">
                          <div className="text-sm">
                            {cluster.nodes.length} node{cluster.nodes.length !== 1 ? 's' : ''}
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <div className={`w-2 h-2 rounded-full ${health.healthy === health.total ? 'bg-green-500' : health.healthy > 0 ? 'bg-yellow-500' : 'bg-red-500'}`} />
                            <span className="text-sm">
                              {health.healthy}/{health.total} healthy
                            </span>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <div className="text-sm text-gray-500">
                            {new Date(cluster.created_at).toLocaleDateString()}
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation()
                                window.location.href = `/clusters/${cluster.id}`
                              }}
                            >
                              <ArrowRight className="w-4 h-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={(e) => {
                                e.stopPropagation()
                                handleDelete(cluster.id)
                              }}
                            >
                              <Trash2 className="w-4 h-4 text-red-500" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Node Replication Status */}
      {syncStatus && syncStatus.nodes.length > 0 && (
        <Card>
          <CardHeader>
            <h3 className="text-lg font-semibold">Node Replication Status</h3>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700">
                    <th className="text-left py-3 px-4 font-medium">Node ID</th>
                    <th className="text-left py-3 px-4 font-medium">Last Sync</th>
                    <th className="text-left py-3 px-4 font-medium">Lag</th>
                    <th className="text-left py-3 px-4 font-medium">Pending</th>
                    <th className="text-left py-3 px-4 font-medium">Failed</th>
                  </tr>
                </thead>
                <tbody>
                  {syncStatus.nodes.map((node) => (
                    <tr key={node.node_id} className="border-b border-gray-100 dark:border-gray-800">
                      <td className="py-3 px-4 font-mono text-sm">{node.node_id}</td>
                      <td className="py-3 px-4 text-sm">
                        {node.last_replication ? new Date(node.last_replication).toLocaleString() : 'Never'}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`text-sm ${node.lag_ms > 60000 ? 'text-red-500' : node.lag_ms > 10000 ? 'text-yellow-500' : 'text-green-500'}`}>
                          {node.lag_ms > 60000 ? `${Math.round(node.lag_ms / 60000)}m` :
                           node.lag_ms > 1000 ? `${Math.round(node.lag_ms / 1000)}s` :
                           `${node.lag_ms}ms`}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-sm">{node.pending_events}</td>
                      <td className="py-3 px-4">
                        <span className={node.failed_attempts > 0 ? 'text-red-500' : ''}>
                          {node.failed_attempts}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
