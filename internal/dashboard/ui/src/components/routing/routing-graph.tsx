import { useMemo } from 'react'
import {
  ReactFlow,
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  MarkerType,
  useNodesState,
  useEdgesState,
  Position,
  Handle,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import type { RoutingConfig, UpstreamStatus, WafConfig } from '@/lib/api'
import { Globe, Server, Route as RouteIcon, Shield, Lock, Unlock, Activity, Heart } from 'lucide-react'

// --- Helpers ---

function extractPort(addr: string): string {
  if (!addr) return ''
  const m = addr.match(/:(\d+)$/)
  return m ? m[1] : addr
}

function extractHost(url: string): string {
  try {
    const u = new URL(url)
    return u.host
  } catch {
    return url
  }
}

function isTLS(url: string): boolean {
  return url.startsWith('https://')
}

// --- Custom Node Components ---

function ClientNode({ data }: NodeProps) {
  return (
    <div className="rounded-xl border-2 border-blue-500/60 bg-blue-950/80 px-5 py-3 text-center shadow-lg shadow-blue-500/10 min-w-[150px]">
      <Globe className="mx-auto mb-1.5 text-blue-400" size={22} />
      <div className="text-sm font-semibold text-blue-200">{String(data.label)}</div>
      <div className="flex items-center justify-center gap-2 mt-1.5">
        {Boolean(data.httpPort) && (
          <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-900/60 text-blue-300 font-mono">
            :{String(data.httpPort)}
          </span>
        )}
        {Boolean(data.httpsPort) && (
          <span className="text-[9px] px-1.5 py-0.5 rounded bg-yellow-900/60 text-yellow-300 font-mono flex items-center gap-0.5">
            <Lock size={8} />:{String(data.httpsPort)}
          </span>
        )}
      </div>
      <Handle type="source" position={Position.Right} className="!bg-blue-400 !w-2.5 !h-2.5" />
    </div>
  )
}

function WafNode({ data }: NodeProps) {
  const tlsEnabled = Boolean(data.tlsEnabled)
  return (
    <div className="rounded-xl border-2 border-emerald-500/60 bg-emerald-950/80 px-5 py-3 text-center shadow-lg shadow-emerald-500/10 min-w-[180px]">
      <Handle type="target" position={Position.Left} className="!bg-emerald-400 !w-2.5 !h-2.5" />
      <Shield className="mx-auto mb-1.5 text-emerald-400" size={22} />
      <div className="text-sm font-semibold text-emerald-200">{String(data.label)}</div>
      <div className="text-[10px] text-emerald-400/70 mt-0.5">{String(data.subtitle)}</div>
      <div className="flex items-center justify-center gap-1.5 mt-1.5">
        <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-900/60 text-emerald-300 font-mono">
          {String(data.mode)}
        </span>
        {tlsEnabled ? (
          <span className="text-[9px] px-1.5 py-0.5 rounded bg-yellow-900/60 text-yellow-300 flex items-center gap-0.5">
            <Lock size={8} /> TLS
          </span>
        ) : (
          <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-800/60 text-slate-400 flex items-center gap-0.5">
            <Unlock size={8} /> HTTP
          </span>
        )}
      </div>
      <Handle type="source" position={Position.Right} className="!bg-emerald-400 !w-2.5 !h-2.5" />
    </div>
  )
}

function VHostNode({ data }: NodeProps) {
  const hasTLS = Boolean(data.hasTLS)
  return (
    <div className="rounded-xl border-2 border-violet-500/60 bg-violet-950/80 px-4 py-2.5 shadow-lg shadow-violet-500/10 min-w-[170px]">
      <Handle type="target" position={Position.Left} className="!bg-violet-400 !w-2.5 !h-2.5" />
      <div className="flex items-center gap-1.5 mb-1">
        <Globe size={14} className="text-violet-400" />
        <span className="text-xs font-semibold text-violet-200">{String(data.label)}</span>
        {hasTLS && (
          <span className="text-[8px] px-1 py-0.5 rounded bg-yellow-900/60 text-yellow-300 flex items-center gap-0.5">
            <Lock size={7} />
          </span>
        )}
      </div>
      {Array.isArray(data.domains) && (data.domains as string[]).map((d: string, i: number) => (
        <div key={i} className="text-[10px] text-violet-300/70 pl-5 font-mono">{String(d)}</div>
      ))}
      <Handle type="source" position={Position.Right} className="!bg-violet-400 !w-2.5 !h-2.5" />
    </div>
  )
}

function RouteNode({ data }: NodeProps) {
  return (
    <div className="rounded-lg border border-amber-500/50 bg-amber-950/80 px-3 py-2 shadow-md min-w-[130px]">
      <Handle type="target" position={Position.Left} className="!bg-amber-400 !w-2 !h-2" />
      <div className="flex items-center gap-1.5">
        <RouteIcon size={12} className="text-amber-400" />
        <span className="text-xs font-mono text-amber-200">{String(data.label)}</span>
      </div>
      <div className="flex items-center gap-1.5 mt-0.5 pl-4">
        {Boolean(data.strip) && (
          <span className="text-[8px] px-1 rounded bg-amber-900/50 text-amber-400/80">strip</span>
        )}
        <span className="text-[9px] text-amber-400/50">&rarr; {String(data.upstream)}</span>
      </div>
      <Handle type="source" position={Position.Right} className="!bg-amber-400 !w-2 !h-2" />
    </div>
  )
}

function UpstreamNode({ data }: NodeProps) {
  const healthy = data.healthy as number
  const total = data.total as number
  const strategy = data.strategy as string
  const allHealthy = healthy === total
  const hcPath = data.hcPath as string
  const hcEnabled = Boolean(data.hcEnabled)

  return (
    <div className={`rounded-xl border-2 px-4 py-2.5 shadow-lg min-w-[175px] ${
      allHealthy
        ? 'border-cyan-500/60 bg-cyan-950/80 shadow-cyan-500/10'
        : 'border-red-500/60 bg-red-950/80 shadow-red-500/10'
    }`}>
      <Handle type="target" position={Position.Left} className={`!w-2.5 !h-2.5 ${allHealthy ? '!bg-cyan-400' : '!bg-red-400'}`} />
      <div className="flex items-center gap-1.5 mb-1">
        <Server size={14} className={allHealthy ? 'text-cyan-400' : 'text-red-400'} />
        <span className="text-xs font-semibold text-slate-200">{String(data.label)}</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-[9px] px-1 rounded bg-slate-800/80 text-slate-400">{strategy}</span>
        <span className={`text-[9px] font-medium ${allHealthy ? 'text-cyan-400' : 'text-red-400'}`}>
          {healthy}/{total}
        </span>
      </div>
      {hcEnabled && (
        <div className="flex items-center gap-1 mt-1 text-[9px] text-slate-500">
          <Heart size={8} className="text-pink-400" /> {hcPath}
        </div>
      )}
      <Handle type="source" position={Position.Right} className={`!w-2.5 !h-2.5 ${allHealthy ? '!bg-cyan-400' : '!bg-red-400'}`} />
    </div>
  )
}

function TargetNode({ data }: NodeProps) {
  const healthy = data.healthy as boolean
  const circuit = data.circuit as string
  const conns = data.conns as number
  const weight = data.weight as number
  const url = String(data.label)
  const ssl = isTLS(url)
  const host = extractHost(url)

  return (
    <div className={`rounded-lg border px-3 py-2 shadow-md min-w-[200px] ${
      healthy
        ? 'border-green-500/50 bg-green-950/80'
        : 'border-red-500/50 bg-red-950/80'
    }`}>
      <Handle type="target" position={Position.Left} className={`!w-2 !h-2 ${healthy ? '!bg-green-400' : '!bg-red-400'}`} />
      <div className="flex items-center gap-1">
        {ssl ? <Lock size={10} className="text-yellow-400" /> : <Unlock size={10} className="text-slate-500" />}
        <span className="text-[11px] font-mono text-slate-300">{host}</span>
      </div>
      <div className="flex flex-wrap gap-1.5 mt-1">
        <span className={`text-[8px] px-1 rounded ${healthy ? 'bg-green-900/60 text-green-400' : 'bg-red-900/60 text-red-400'}`}>
          {healthy ? 'healthy' : 'down'}
        </span>
        <span className={`text-[8px] px-1 rounded ${
          circuit === 'closed' ? 'bg-slate-800/60 text-slate-500' :
          circuit === 'open' ? 'bg-red-900/60 text-red-400' :
          'bg-yellow-900/60 text-yellow-400'
        }`}>
          cb:{circuit}
        </span>
        {weight > 1 && (
          <span className="text-[8px] px-1 rounded bg-blue-900/60 text-blue-300">w:{weight}</span>
        )}
        {conns > 0 && (
          <span className="text-[8px] px-1 rounded bg-purple-900/60 text-purple-300 flex items-center gap-0.5">
            <Activity size={7} />{conns}
          </span>
        )}
      </div>
    </div>
  )
}

const nodeTypes = {
  client: ClientNode,
  waf: WafNode,
  vhost: VHostNode,
  route: RouteNode,
  upstream: UpstreamNode,
  target: TargetNode,
}

// --- Graph Builder ---

interface Props {
  routing: RoutingConfig
  upstreams?: UpstreamStatus[]
  wafConfig?: WafConfig
}

export function RoutingGraph({ routing, upstreams, wafConfig }: Props) {
  const { initialNodes, initialEdges } = useMemo(() => {
    const nodes: Node[] = []
    const edges: Edge[] = []

    const edgeStyle = { stroke: '#475569', strokeWidth: 1.5 }
    const tlsEdgeStyle = { stroke: '#eab308', strokeWidth: 2, strokeDasharray: '6 3' }

    let y = 0
    const xClient = 0
    const xWaf = 240
    const xVhost = 500
    const xRoute = 720
    const xUpstream = 960
    const xTarget = 1220

    // Extract TLS info from WAF config
    const tlsEnabled = wafConfig?.tls?.enabled === true
    const httpsPort = tlsEnabled ? extractPort(wafConfig?.tls?.listen || ':8443') : ''
    const listenPort = extractPort(':8088')

    // Client node — shows inbound ports
    nodes.push({
      id: 'client',
      type: 'client',
      position: { x: xClient, y: 120 },
      data: { label: 'Incoming Traffic', httpPort: listenPort, httpsPort },
    })

    // WAF node — shows mode + TLS status
    nodes.push({
      id: 'waf',
      type: 'waf',
      position: { x: xWaf, y: 100 },
      data: {
        label: 'GuardianWAF',
        subtitle: '13 security layers',
        mode: wafConfig?.mode || 'enforce',
        tlsEnabled,
      },
    })

    edges.push({
      id: 'client-waf',
      source: 'client',
      target: 'waf',
      style: tlsEnabled ? tlsEdgeStyle : edgeStyle,
      label: tlsEnabled ? 'TLS' : 'HTTP',
      labelStyle: { fill: tlsEnabled ? '#eab308' : '#64748b', fontSize: 10 },
      labelBgStyle: { fill: '#0f172a', fillOpacity: 0.8 },
      markerEnd: { type: MarkerType.ArrowClosed, color: tlsEnabled ? '#eab308' : '#475569' },
      animated: true,
    })

    // Build upstream health map
    const healthMap = new Map<string, UpstreamStatus>()
    upstreams?.forEach(u => healthMap.set(u.name, u))

    // Virtual Hosts
    y = 0
    routing.virtual_hosts?.forEach((vh, vi) => {
      const vhId = `vh-${vi}`
      const vhHasTLS = Boolean(vh.tls?.cert_file)
      nodes.push({
        id: vhId,
        type: 'vhost',
        position: { x: xVhost, y },
        data: { label: `VHost ${vi + 1}`, domains: vh.domains, hasTLS: vhHasTLS },
      })
      edges.push({
        id: `waf-${vhId}`,
        source: 'waf',
        target: vhId,
        style: vhHasTLS ? tlsEdgeStyle : edgeStyle,
        markerEnd: { type: MarkerType.ArrowClosed, color: vhHasTLS ? '#eab308' : '#475569' },
      })

      // VHost routes
      vh.routes?.forEach((r, ri) => {
        const rId = `vh${vi}-route-${ri}`
        nodes.push({
          id: rId,
          type: 'route',
          position: { x: xRoute, y: y + ri * 55 },
          data: { label: r.path, strip: r.strip_prefix, upstream: r.upstream },
        })
        edges.push({
          id: `${vhId}-${rId}`,
          source: vhId,
          target: rId,
          style: edgeStyle,
          markerEnd: { type: MarkerType.ArrowClosed, color: '#475569' },
        })
        const usId = `upstream-${r.upstream}`
        edges.push({
          id: `${rId}-${usId}`,
          source: rId,
          target: usId,
          style: edgeStyle,
          markerEnd: { type: MarkerType.ArrowClosed, color: '#475569' },
          animated: true,
        })
      })

      y += Math.max(vh.routes?.length || 1, 1) * 60 + 30
    })

    // Default routes
    const defaultY = y
    routing.routes?.forEach((r, ri) => {
      const rId = `default-route-${ri}`
      nodes.push({
        id: rId,
        type: 'route',
        position: { x: xRoute, y: defaultY + ri * 55 },
        data: { label: r.path, strip: r.strip_prefix, upstream: r.upstream },
      })
      edges.push({
        id: `waf-${rId}`,
        source: 'waf',
        target: rId,
        style: edgeStyle,
        markerEnd: { type: MarkerType.ArrowClosed, color: '#475569' },
      })
      const usId = `upstream-${r.upstream}`
      edges.push({
        id: `${rId}-${usId}`,
        source: rId,
        target: usId,
        style: edgeStyle,
        markerEnd: { type: MarkerType.ArrowClosed, color: '#475569' },
        animated: true,
      })
    })

    // Upstreams
    let uy = 0
    routing.upstreams?.forEach((u) => {
      const usId = `upstream-${u.name}`
      const health = healthMap.get(u.name)
      nodes.push({
        id: usId,
        type: 'upstream',
        position: { x: xUpstream, y: uy },
        data: {
          label: u.name,
          strategy: u.load_balancer || 'round_robin',
          healthy: health?.healthy_count ?? u.targets.length,
          total: health?.total_count ?? u.targets.length,
          hcEnabled: u.health_check?.enabled,
          hcPath: u.health_check?.path || '/',
        },
      })

      // Targets — show per-target details
      u.targets.forEach((t, ti) => {
        const tId = `target-${u.name}-${ti}`
        const targetHealth = health?.targets?.find(th => th.url === t.url)
        nodes.push({
          id: tId,
          type: 'target',
          position: { x: xTarget, y: uy + ti * 60 },
          data: {
            label: t.url,
            weight: t.weight,
            healthy: targetHealth?.healthy ?? true,
            circuit: targetHealth?.circuit_state ?? 'closed',
            conns: targetHealth?.active_conns ?? 0,
          },
        })
        const targetSSL = isTLS(t.url)
        edges.push({
          id: `${usId}-${tId}`,
          source: usId,
          target: tId,
          style: targetSSL ? { ...edgeStyle, stroke: '#eab308' } : edgeStyle,
          markerEnd: { type: MarkerType.ArrowClosed, color: targetSSL ? '#eab308' : '#475569' },
        })
      })

      uy += Math.max(u.targets.length, 1) * 60 + 30
    })

    return { initialNodes: nodes, initialEdges: edges }
  }, [routing, upstreams, wafConfig])

  const [nodes, , onNodesChange] = useNodesState(initialNodes)
  const [edges, , onEdgesChange] = useEdgesState(initialEdges)

  return (
    <div className="h-[600px] w-full rounded-xl border border-border bg-slate-950/50">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        minZoom={0.2}
        maxZoom={2.5}
        proOptions={{ hideAttribution: true }}
        className="[&_.react-flow__node]:!cursor-grab"
      >
        <Background color="#1e293b" gap={20} size={1} />
        <Controls
          className="!bg-slate-800 !border-slate-600 !rounded-lg [&_button]:!bg-slate-700 [&_button]:!border-slate-600 [&_button]:!text-slate-300 [&_button:hover]:!bg-slate-600"
          showInteractive={false}
        />
        <MiniMap
          className="!bg-slate-900 !border-slate-700 !rounded-lg"
          nodeColor={(n) => {
            switch (n.type) {
              case 'client': return '#3b82f6'
              case 'waf': return '#10b981'
              case 'vhost': return '#8b5cf6'
              case 'route': return '#f59e0b'
              case 'upstream': return '#06b6d4'
              case 'target': return '#22c55e'
              default: return '#64748b'
            }
          }}
        />
      </ReactFlow>
      {/* Legend */}
      <div className="flex items-center gap-4 px-3 py-1.5 text-[10px] text-slate-500 border-t border-border">
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-500" /> Clients</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-emerald-500" /> WAF</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-violet-500" /> VHost</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-amber-500" /> Route</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-cyan-500" /> Upstream</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-green-500" /> Target</span>
        <span className="flex items-center gap-1 ml-auto"><Lock size={9} className="text-yellow-400" /> TLS/SSL</span>
      </div>
    </div>
  )
}
