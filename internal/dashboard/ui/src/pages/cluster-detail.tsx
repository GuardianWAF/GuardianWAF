import { useState, useEffect } from 'react'
import { useParams } from 'react-router'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { useToast } from '@/components/ui/toast'
import { api, Cluster, ClusterNode } from '@/lib/api'
import { ArrowLeft, Plus, Trash2, RefreshCw, Server, CheckCircle, XCircle, Activity } from 'lucide-react'

export default function ClusterDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [cluster, setCluster] = useState<Cluster | null>(null)
  const [nodes, setNodes] = useState<ClusterNode[]>([])
  const [allNodes, setAllNodes] = useState<ClusterNode[]>([])
  const [loading, setLoading] = useState(true)
  const [showAddNode, setShowAddNode] = useState(false)
  const [newNode, setNewNode] = useState({ id: '', name: '', address: '' })
  const { toast } = useToast()

  useEffect(() => {
    if (id) {
      loadData()
      const interval = setInterval(loadData, 10000)
      return () => clearInterval(interval)
    }
  }, [id])

  const loadData = async () => {
    try {
      const [clusterData, nodesData, allNodesData] = await Promise.all([
        api.getCluster(id!),
        api.getNodes(),
        api.getNodes()
      ])
      setCluster(clusterData)
      setAllNodes(allNodesData)

      // Filter nodes that belong to this cluster
      const clusterNodeIds = new Set(clusterData.nodes)
      const clusterNodes = nodesData.filter(n => clusterNodeIds.has(n.id))
      setNodes(clusterNodes)
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to load cluster details',
        variant: 'destructive'
      })
    } finally {
      setLoading(false)
    }
  }

  const handleAddNode = async () => {
    if (!newNode.id || !newNode.name || !newNode.address) {
      toast({
        title: 'Error',
        description: 'Please fill in all fields',
        variant: 'destructive'
      })
      return
    }

    try {
      await api.joinCluster(id!, {
        id: newNode.id,
        name: newNode.name,
        address: newNode.address
      })
      toast({ title: 'Success', description: 'Node added to cluster' })
      setNewNode({ id: '', name: '', address: '' })
      setShowAddNode(false)
      loadData()
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to add node',
        variant: 'destructive'
      })
    }
  }

  const handleRemoveNode = async (nodeId: string) => {
    if (!confirm(`Are you sure you want to remove node ${nodeId} from this cluster?`)) return

    try {
      await api.leaveCluster(id!, nodeId)
      toast({ title: 'Success', description: 'Node removed from cluster' })
      loadData()
    } catch (error) {
      toast({
        title: 'Error',
        description: 'Failed to remove node',
        variant: 'destructive'
      })
    }
  }

  const handleRefresh = () => {
    setLoading(true)
    loadData()
  }

  const getScopeColor = (scope: string) => {
    switch (scope) {
      case 'all': return 'bg-green-500'
      case 'tenants': return 'bg-blue-500'
      case 'rules': return 'bg-purple-500'
      case 'config': return 'bg-orange-500'
      default: return 'bg-gray-500'
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg">Loading cluster details...</div>
      </div>
    )
  }

  if (!cluster) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg text-red-500">Cluster not found</div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="outline" onClick={() => window.location.href = '/clusters'}>
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back
          </Button>
          <div>
            <h1 className="text-3xl font-bold">{cluster.name}</h1>
            <div className="text-sm text-gray-500">ID: {cluster.id}</div>
          </div>
        </div>
        <Button variant="outline" onClick={handleRefresh}>
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Cluster Info */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <Activity className="w-5 h-5 text-blue-500" />
              <div>
                <div className="text-sm text-gray-500">Sync Scope</div>
                <Badge className={getScopeColor(cluster.sync_scope)}>
                  {cluster.sync_scope}
                </Badge>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <Server className="w-5 h-5 text-green-500" />
              <div>
                <div className="text-sm text-gray-500">Total Nodes</div>
                <div className="text-xl font-bold">{nodes.length}</div>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <CheckCircle className="w-5 h-5 text-green-500" />
              <div>
                <div className="text-sm text-gray-500">Healthy Nodes</div>
                <div className="text-xl font-bold">
                  {nodes.filter(n => n.healthy).length} / {nodes.length}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Description */}
      {cluster.description && (
        <Card>
          <CardHeader>
            <CardTitle>Description</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-gray-600 dark:text-gray-300">{cluster.description}</p>
          </CardContent>
        </Card>
      )}

      {/* Nodes Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Cluster Nodes</CardTitle>
            <Button onClick={() => setShowAddNode(true)}>
              <Plus className="w-4 h-4 mr-2" />
              Add Node
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {nodes.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              No nodes in this cluster yet.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700">
                    <th className="text-left py-3 px-4 font-medium">Node</th>
                    <th className="text-left py-3 px-4 font-medium">Address</th>
                    <th className="text-left py-3 px-4 font-medium">Status</th>
                    <th className="text-left py-3 px-4 font-medium">Version</th>
                    <th className="text-left py-3 px-4 font-medium">Last Seen</th>
                    <th className="text-left py-3 px-4 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {nodes.map((node) => (
                    <tr
                      key={node.id}
                      className="border-b border-gray-100 dark:border-gray-800"
                    >
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <Server className="w-4 h-4 text-gray-400" />
                          <div>
                            <div className="font-medium">{node.name}</div>
                            <div className="text-xs text-gray-400 font-mono">{node.id}</div>
                            {node.is_local && (
                              <Badge variant="outline" className="text-xs mt-1">Local</Badge>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <code className="text-sm bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">
                          {node.address}
                        </code>
                      </td>
                      <td className="py-3 px-4">
                        {node.healthy ? (
                          <div className="flex items-center gap-2 text-green-500">
                            <CheckCircle className="w-4 h-4" />
                            <span className="text-sm">Healthy</span>
                          </div>
                        ) : (
                          <div className="flex items-center gap-2 text-red-500">
                            <XCircle className="w-4 h-4" />
                            <span className="text-sm">Unhealthy</span>
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4 text-sm">
                        {node.version || 'Unknown'}
                      </td>
                      <td className="py-3 px-4 text-sm text-gray-500">
                        {node.last_seen
                          ? new Date(node.last_seen).toLocaleString()
                          : 'Never'}
                      </td>
                      <td className="py-3 px-4">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleRemoveNode(node.id)}
                          disabled={node.is_local}
                          title={node.is_local ? 'Cannot remove local node' : 'Remove from cluster'}
                        >
                          <Trash2 className="w-4 h-4 text-red-500" />
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Add Node Form */}
      {showAddNode && (
        <Card>
          <CardHeader>
            <CardTitle>Add Node to Cluster</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <Label htmlFor="node-id">Node ID</Label>
                  <Input
                    id="node-id"
                    placeholder="e.g., node-2"
                    value={newNode.id}
                    onChange={(e) => setNewNode({ ...newNode, id: e.target.value })}
                  />
                </div>
                <div>
                  <Label htmlFor="node-name">Name</Label>
                  <Input
                    id="node-name"
                    placeholder="e.g., WAF Secondary"
                    value={newNode.name}
                    onChange={(e) => setNewNode({ ...newNode, name: e.target.value })}
                  />
                </div>
                <div>
                  <Label htmlFor="node-address">Address</Label>
                  <Input
                    id="node-address"
                    placeholder="e.g., https://waf-2.example.com:9444"
                    value={newNode.address}
                    onChange={(e) => setNewNode({ ...newNode, address: e.target.value })}
                  />
                </div>
              </div>
              <div className="flex gap-2">
                <Button onClick={handleAddNode}>
                  <Plus className="w-4 h-4 mr-2" />
                  Add Node
                </Button>
                <Button variant="outline" onClick={() => setShowAddNode(false)}>
                  Cancel
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Available Nodes */}
      <Card>
        <CardHeader>
          <CardTitle>All Known Nodes</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700">
                  <th className="text-left py-3 px-4 font-medium">Node</th>
                  <th className="text-left py-3 px-4 font-medium">Address</th>
                  <th className="text-left py-3 px-4 font-medium">Status</th>
                  <th className="text-left py-3 px-4 font-medium">In Cluster</th>
                </tr>
              </thead>
              <tbody>
                {allNodes.map((node) => {
                  const inCluster = cluster.nodes.includes(node.id)
                  return (
                    <tr
                      key={node.id}
                      className="border-b border-gray-100 dark:border-gray-800"
                    >
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <Server className="w-4 h-4 text-gray-400" />
                          <div>
                            <div className="font-medium">{node.name}</div>
                            <div className="text-xs text-gray-400 font-mono">{node.id}</div>
                            {node.is_local && (
                              <Badge variant="outline" className="text-xs mt-1">Local</Badge>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <code className="text-sm bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">
                          {node.address}
                        </code>
                      </td>
                      <td className="py-3 px-4">
                        {node.healthy ? (
                          <div className="flex items-center gap-2 text-green-500">
                            <CheckCircle className="w-4 h-4" />
                            <span className="text-sm">Healthy</span>
                          </div>
                        ) : (
                          <div className="flex items-center gap-2 text-red-500">
                            <XCircle className="w-4 h-4" />
                            <span className="text-sm">Unhealthy</span>
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {inCluster ? (
                          <Badge className="bg-green-500">Yes</Badge>
                        ) : (
                          <Badge variant="outline">No</Badge>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
