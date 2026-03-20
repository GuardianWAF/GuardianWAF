import { useState, useEffect, useCallback } from 'react'
import { api } from '@/lib/api'
import type { RoutingConfig, UpstreamConfig, UpstreamStatus, VirtualHostConfig, RouteConfig, WafConfig } from '@/lib/api'
import { cn } from '@/lib/utils'
import { Section } from '@/components/config/section'
import { Input } from '@/components/ui/input'
import { Select, SelectOption } from '@/components/ui/select'
import { Button } from '@/components/ui/button'
import { Plus, Trash2, Loader2, Server, Globe, Route, X, GitBranch, Settings2, Container, RefreshCw } from 'lucide-react'
import { RoutingGraph } from '@/components/routing/routing-graph'

// Deep clone helper
function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v))
}

function emptyUpstream(): UpstreamConfig {
  return {
    name: '',
    load_balancer: 'round_robin',
    targets: [{ url: '', weight: 1 }],
    health_check: { enabled: false, interval: '10s', timeout: '5s', path: '/' },
  }
}

function emptyVirtualHost(): VirtualHostConfig {
  return {
    domains: [],
    tls: { cert_file: '', key_file: '' },
    routes: [],
  }
}

function emptyRoute(): RouteConfig {
  return { path: '/', upstream: '', strip_prefix: false }
}

export default function RoutingPage() {
  const [routing, setRouting] = useState<RoutingConfig | null>(null)
  const [upstreamHealth, setUpstreamHealth] = useState<UpstreamStatus[]>([])
  const [wafConfig, setWafConfig] = useState<WafConfig | null>(null)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [view, setView] = useState<'form' | 'graph' | 'services'>('graph')
  const [dockerServices, setDockerServices] = useState<any[]>([])
  const [dockerEnabled, setDockerEnabled] = useState(false)

  // Domain add input per vhost
  const [domainInputs, setDomainInputs] = useState<Record<number, string>>({})
  // Target add inputs per upstream
  const [targetInputs, setTargetInputs] = useState<Record<number, { url: string; weight: number }>>({})

  const fetchData = useCallback(() => {
    api
      .getRouting()
      .then((data) => {
        setRouting(data)
      })
      .catch(() => setError('Failed to load routing configuration'))
    api.getUpstreams().then(setUpstreamHealth).catch(() => {})
    api.getConfig().then(setWafConfig).catch(() => {})
    fetch('/api/v1/docker/services').then(r => r.json()).then(data => {
      setDockerEnabled(data.enabled ?? false)
      setDockerServices(data.services ?? [])
    }).catch(() => {})
  }, [])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const upstreamNames = (routing?.upstreams || []).map((u) => u.name).filter(Boolean)

  /* ---- Upstream mutations ---- */
  const updateUpstream = (idx: number, patch: Partial<UpstreamConfig>) => {
    setRouting((prev) => {
      if (!prev) return prev
      const next = clone(prev)
      next.upstreams[idx] = { ...next.upstreams[idx], ...patch }
      return next
    })
  }

  const addUpstream = () => {
    setRouting((prev) => {
      if (!prev) return prev
      return { ...prev, upstreams: [...prev.upstreams, emptyUpstream()] }
    })
  }

  const removeUpstream = (idx: number) => {
    setRouting((prev) => {
      if (!prev) return prev
      const next = clone(prev)
      next.upstreams.splice(idx, 1)
      return next
    })
  }

  const addTarget = (upIdx: number) => {
    const input = targetInputs[upIdx]
    if (!input?.url.trim()) return
    setRouting((prev) => {
      if (!prev) return prev
      const next = clone(prev)
      next.upstreams[upIdx].targets.push({ url: input.url.trim(), weight: input.weight || 1 })
      return next
    })
    setTargetInputs((prev) => ({ ...prev, [upIdx]: { url: '', weight: 1 } }))
  }

  const removeTarget = (upIdx: number, tIdx: number) => {
    setRouting((prev) => {
      if (!prev) return prev
      const next = clone(prev)
      next.upstreams[upIdx].targets.splice(tIdx, 1)
      return next
    })
  }

  const updateTarget = (upIdx: number, tIdx: number, field: 'url' | 'weight', value: string | number) => {
    setRouting((prev) => {
      if (!prev) return prev
      const next = clone(prev)
      if (field === 'url') next.upstreams[upIdx].targets[tIdx].url = value as string
      else next.upstreams[upIdx].targets[tIdx].weight = value as number
      return next
    })
  }

  /* ---- Virtual Host mutations ---- */
  const addVHost = () => {
    setRouting((prev) => {
      if (!prev) return prev
      return { ...prev, virtual_hosts: [...prev.virtual_hosts, emptyVirtualHost()] }
    })
  }

  const removeVHost = (idx: number) => {
    setRouting((prev) => {
      if (!prev) return prev
      const next = clone(prev)
      next.virtual_hosts.splice(idx, 1)
      return next
    })
  }

  const addDomain = (vhIdx: number) => {
    const domain = domainInputs[vhIdx]?.trim()
    if (!domain) return
    setRouting((prev) => {
      if (!prev) return prev
      const next = clone(prev)
      if (!next.virtual_hosts[vhIdx].domains.includes(domain)) {
        next.virtual_hosts[vhIdx].domains.push(domain)
      }
      return next
    })
    setDomainInputs((prev) => ({ ...prev, [vhIdx]: '' }))
  }

  const removeDomain = (vhIdx: number, domain: string) => {
    setRouting((prev) => {
      if (!prev) return prev
      const next = clone(prev)
      next.virtual_hosts[vhIdx].domains = next.virtual_hosts[vhIdx].domains.filter(
        (d) => d !== domain,
      )
      return next
    })
  }

  const addVHostRoute = (vhIdx: number) => {
    setRouting((prev) => {
      if (!prev) return prev
      const next = clone(prev)
      next.virtual_hosts[vhIdx].routes.push(emptyRoute())
      return next
    })
  }

  const removeVHostRoute = (vhIdx: number, rIdx: number) => {
    setRouting((prev) => {
      if (!prev) return prev
      const next = clone(prev)
      next.virtual_hosts[vhIdx].routes.splice(rIdx, 1)
      return next
    })
  }

  const updateVHostRoute = (vhIdx: number, rIdx: number, patch: Partial<RouteConfig>) => {
    setRouting((prev) => {
      if (!prev) return prev
      const next = clone(prev)
      next.virtual_hosts[vhIdx].routes[rIdx] = {
        ...next.virtual_hosts[vhIdx].routes[rIdx],
        ...patch,
      }
      return next
    })
  }

  /* ---- Default Route mutations ---- */
  const addDefaultRoute = () => {
    setRouting((prev) => {
      if (!prev) return prev
      return { ...prev, routes: [...prev.routes, emptyRoute()] }
    })
  }

  const removeDefaultRoute = (idx: number) => {
    setRouting((prev) => {
      if (!prev) return prev
      const next = clone(prev)
      next.routes.splice(idx, 1)
      return next
    })
  }

  const updateDefaultRoute = (idx: number, patch: Partial<RouteConfig>) => {
    setRouting((prev) => {
      if (!prev) return prev
      const next = clone(prev)
      next.routes[idx] = { ...next.routes[idx], ...patch }
      return next
    })
  }

  /* ---- Save ---- */
  const handleSave = async () => {
    if (!routing) return
    setSaving(true)
    setError(null)
    setSuccess(null)
    try {
      await api.updateRouting(routing)
      setSuccess('Routing saved and proxy rebuilt')
      setTimeout(() => setSuccess(null), 3000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save routing')
    } finally {
      setSaving(false)
    }
  }

  if (!routing) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-4 pb-20">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-foreground">Routing Management</h1>
        <div className="flex gap-1 rounded-lg border border-border bg-muted/50 p-0.5">
          <button
            onClick={() => setView('graph')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              view === 'graph'
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            <GitBranch size={14} />
            Topology
          </button>
          <button
            onClick={() => setView('services')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              view === 'services'
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            <Container size={14} />
            Backends
            {dockerServices.length > 0 && (
              <span className="ml-0.5 text-[9px] bg-accent/20 px-1 rounded-full">{dockerServices.length}</span>
            )}
          </button>
          <button
            onClick={() => setView('form')}
            className={cn(
              'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-colors',
              view === 'form'
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            <Settings2 size={14} />
            Configure
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      )}
      {success && (
        <div className="rounded-lg border border-success/30 bg-success/10 px-4 py-3 text-sm text-success">
          {success}
        </div>
      )}

      {/* ==================== Graph View ==================== */}
      {view === 'graph' && routing && (
        <RoutingGraph routing={routing} upstreams={upstreamHealth} wafConfig={wafConfig ?? undefined} />
      )}

      {/* ==================== Backends View ==================== */}
      {view === 'services' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">
              All backends: {(routing?.upstreams?.length || 0)} upstream pool(s), {upstreamHealth.reduce((a, u) => a + u.total_count, 0)} target(s)
              {dockerEnabled && `, ${dockerServices.length} Docker discovered`}
            </span>
            <Button size="sm" variant="outline" onClick={fetchData}>
              <RefreshCw size={14} className="mr-1" /> Refresh
            </Button>
          </div>

          {/* === Upstream Pools with Live Health === */}
          <Section title={`Upstream Pools (${upstreamHealth.length})`} defaultOpen>
            {upstreamHealth.length === 0 && (routing?.upstreams?.length || 0) === 0 ? (
              <p className="text-sm text-muted-foreground py-4 text-center">No upstreams configured. Add backends via config, Docker labels, or the Configure tab.</p>
            ) : (
              <div className="space-y-2">
                {(upstreamHealth.length > 0 ? upstreamHealth : (routing?.upstreams || []).map(u => ({
                  name: u.name, strategy: u.load_balancer || 'round_robin',
                  targets: u.targets.map(t => ({ url: t.url, healthy: true, circuit_state: 'closed', active_conns: 0, weight: t.weight })),
                  healthy_count: u.targets.length, total_count: u.targets.length,
                }))).map((u: any, ui: number) => (
                  <div key={ui} className="rounded-lg border border-border bg-card/30 overflow-hidden">
                    <div className="flex items-center gap-3 px-3 py-2 bg-muted/20">
                      <Server size={14} className={u.healthy_count === u.total_count ? 'text-cyan-400' : 'text-red-400'} />
                      <span className="text-sm font-medium text-foreground">{u.name}</span>
                      <span className="text-[10px] px-1.5 rounded bg-slate-800 text-slate-400">{u.strategy}</span>
                      <span className={cn('text-[10px] font-medium', u.healthy_count === u.total_count ? 'text-cyan-400' : 'text-red-400')}>
                        {u.healthy_count}/{u.total_count} healthy
                      </span>
                    </div>
                    <table className="w-full text-xs">
                      <tbody>
                        {(u.targets || []).map((t: any, ti: number) => (
                          <tr key={ti} className="border-t border-border/30 hover:bg-muted/10">
                            <td className="px-3 py-1.5 font-mono text-cyan-300 w-1/3">{t.url}</td>
                            <td className="px-3 py-1.5">
                              <span className={cn('text-[9px] px-1 rounded', t.healthy ? 'bg-green-900/40 text-green-400' : 'bg-red-900/40 text-red-400')}>
                                {t.healthy ? 'healthy' : 'down'}
                              </span>
                            </td>
                            <td className="px-3 py-1.5 text-muted-foreground">cb: {t.circuit_state}</td>
                            <td className="px-3 py-1.5 text-muted-foreground">w: {t.weight}</td>
                            <td className="px-3 py-1.5 text-muted-foreground">{t.active_conns > 0 ? `${t.active_conns} conn` : ''}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ))}
              </div>
            )}
          </Section>

          {/* === Docker Discovered === */}
          <Section title={`Docker Discovery ${dockerEnabled ? `(${dockerServices.length} found)` : '(disabled)'}`} defaultOpen={dockerServices.length > 0}>
            {!dockerEnabled ? (
              <div className="text-center py-4">
                <Container size={24} className="mx-auto mb-2 text-muted-foreground" />
                <p className="text-xs text-muted-foreground">
                  Enable <code className="px-1 bg-muted rounded text-[10px]">docker.enabled: true</code> in config and mount <code className="px-1 bg-muted rounded text-[10px]">/var/run/docker.sock</code>
                </p>
              </div>
            ) : dockerServices.length === 0 ? (
              <p className="text-sm text-muted-foreground py-4 text-center">No containers with <code className="px-1 bg-muted rounded text-[10px]">gwaf.enable=true</code> label found.</p>
            ) : (
              <div className="rounded-lg border border-border overflow-hidden">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border bg-muted/30">
                      <th className="text-left px-3 py-2 font-medium text-muted-foreground">Container</th>
                      <th className="text-left px-3 py-2 font-medium text-muted-foreground">Target</th>
                      <th className="text-left px-3 py-2 font-medium text-muted-foreground">Domain</th>
                      <th className="text-left px-3 py-2 font-medium text-muted-foreground">Upstream Pool</th>
                      <th className="text-left px-3 py-2 font-medium text-muted-foreground">Health</th>
                      <th className="text-left px-3 py-2 font-medium text-muted-foreground">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dockerServices.map((svc: any, i: number) => (
                      <tr key={i} className="border-b border-border/30 hover:bg-muted/10">
                        <td className="px-3 py-1.5">
                          <div className="flex items-center gap-1">
                            <Container size={11} className="text-blue-400 shrink-0" />
                            <span className="font-medium text-foreground">{svc.container_name}</span>
                          </div>
                          <div className="text-[9px] text-muted-foreground font-mono">{svc.image}</div>
                        </td>
                        <td className="px-3 py-1.5 font-mono text-cyan-300">{svc.target}</td>
                        <td className="px-3 py-1.5">
                          {svc.host ? <span className="px-1 rounded bg-violet-900/40 text-violet-300">{svc.host}{svc.path !== '/' ? svc.path : ''}</span> : <span className="text-muted-foreground">—</span>}
                        </td>
                        <td className="px-3 py-1.5">
                          <span className="px-1 rounded bg-cyan-900/40 text-cyan-300">{svc.upstream}</span>
                          <span className="text-muted-foreground ml-1">w:{svc.weight}</span>
                        </td>
                        <td className="px-3 py-1.5 text-muted-foreground font-mono">{svc.health_path || '—'}</td>
                        <td className="px-3 py-1.5">
                          <span className={cn('text-[9px] px-1 rounded', svc.status === 'running' ? 'bg-green-900/40 text-green-400' : 'bg-red-900/40 text-red-400')}>
                            {svc.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Section>
        </div>
      )}

      {/* ==================== Form View ==================== */}
      {view === 'form' && <>

      {/* ==================== Upstreams ==================== */}
      <Section title="Upstreams" defaultOpen>
        <div className="space-y-4">
          {(routing.upstreams || []).map((upstream, upIdx) => (
            <div
              key={upIdx}
              className="rounded-md border border-border bg-background p-4 space-y-4"
            >
              <div className="flex items-center gap-3">
                <Server className="h-4 w-4 text-muted-foreground shrink-0" />
                <Input
                  placeholder="Upstream name"
                  value={upstream.name}
                  onChange={(e) => updateUpstream(upIdx, { name: e.target.value })}
                  className="font-mono max-w-xs"
                />
                <Select
                  value={upstream.load_balancer}
                  onChange={(e) =>
                    updateUpstream(upIdx, { load_balancer: e.target.value })
                  }
                  className="w-40"
                >
                  <SelectOption value="round_robin">Round Robin</SelectOption>
                  <SelectOption value="weighted">Weighted</SelectOption>
                  <SelectOption value="least_conn">Least Conn</SelectOption>
                  <SelectOption value="ip_hash">IP Hash</SelectOption>
                </Select>
                <div className="flex-1" />
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => removeUpstream(upIdx)}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>

              {/* Targets */}
              <div className="space-y-2">
                <h5 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Targets
                </h5>
                {(upstream.targets || []).map((target, tIdx) => (
                  <div key={tIdx} className="flex items-center gap-2">
                    <Input
                      placeholder="http://host:port"
                      value={target.url}
                      onChange={(e) =>
                        updateTarget(upIdx, tIdx, 'url', e.target.value)
                      }
                      className="font-mono flex-1"
                    />
                    <Input
                      type="number"
                      value={target.weight}
                      onChange={(e) =>
                        updateTarget(upIdx, tIdx, 'weight', Number(e.target.value))
                      }
                      className="w-20"
                      min={1}
                      title="Weight"
                    />
                    <Button
                      size="icon"
                      variant="ghost"
                      onClick={() => removeTarget(upIdx, tIdx)}
                    >
                      <Trash2 className="h-3.5 w-3.5 text-muted-foreground hover:text-destructive" />
                    </Button>
                  </div>
                ))}

                {/* Add target */}
                <div className="flex items-center gap-2 pt-1">
                  <Input
                    placeholder="http://host:port"
                    value={targetInputs[upIdx]?.url ?? ''}
                    onChange={(e) =>
                      setTargetInputs((prev) => ({
                        ...prev,
                        [upIdx]: { url: e.target.value, weight: prev[upIdx]?.weight ?? 1 },
                      }))
                    }
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') addTarget(upIdx)
                    }}
                    className="font-mono flex-1"
                  />
                  <Input
                    type="number"
                    value={targetInputs[upIdx]?.weight ?? 1}
                    onChange={(e) =>
                      setTargetInputs((prev) => ({
                        ...prev,
                        [upIdx]: { url: prev[upIdx]?.url ?? '', weight: Number(e.target.value) },
                      }))
                    }
                    className="w-20"
                    min={1}
                    title="Weight"
                  />
                  <Button size="sm" variant="secondary" onClick={() => addTarget(upIdx)}>
                    <Plus className="h-3.5 w-3.5" />
                    Add
                  </Button>
                </div>
              </div>
            </div>
          ))}

          <Button variant="secondary" onClick={addUpstream}>
            <Plus className="h-4 w-4" />
            Add Upstream
          </Button>
        </div>
      </Section>

      {/* ==================== Virtual Hosts ==================== */}
      <Section title="Virtual Hosts" defaultOpen>
        <div className="space-y-4">
          {(routing.virtual_hosts || []).map((vhost, vhIdx) => (
            <div
              key={vhIdx}
              className="rounded-md border border-border bg-background p-4 space-y-4"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4 text-muted-foreground shrink-0" />
                  <span className="text-sm font-medium text-foreground">
                    Virtual Host #{vhIdx + 1}
                  </span>
                </div>
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => removeVHost(vhIdx)}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>

              {/* Domains */}
              <div>
                <h5 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                  Domains
                </h5>
                <div className="flex flex-wrap gap-2 mb-3">
                  {(vhost.domains || []).map((domain) => (
                    <span
                      key={domain}
                      className="inline-flex items-center gap-1.5 rounded-full border border-accent/30 bg-accent/10 px-2.5 py-1 text-xs font-mono text-accent"
                    >
                      {domain}
                      <button
                        type="button"
                        onClick={() => removeDomain(vhIdx, domain)}
                        className="rounded-full p-0.5 transition-colors hover:bg-foreground/10"
                        aria-label={`Remove ${domain}`}
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </span>
                  ))}
                  {(vhost.domains || []).length === 0 && (
                    <span className="text-xs text-muted-foreground">No domains</span>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <Input
                    placeholder="example.com"
                    value={domainInputs[vhIdx] ?? ''}
                    onChange={(e) =>
                      setDomainInputs((prev) => ({ ...prev, [vhIdx]: e.target.value }))
                    }
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') addDomain(vhIdx)
                    }}
                    className="font-mono max-w-xs"
                  />
                  <Button size="sm" variant="secondary" onClick={() => addDomain(vhIdx)}>
                    <Plus className="h-3.5 w-3.5" />
                    Add
                  </Button>
                </div>
              </div>

              {/* Routes */}
              <div>
                <h5 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                  Routes
                </h5>
                <div className="space-y-2">
                  {(vhost.routes || []).map((route, rIdx) => (
                    <RouteRow
                      key={rIdx}
                      route={route}
                      upstreamNames={upstreamNames}
                      onChange={(patch) => updateVHostRoute(vhIdx, rIdx, patch)}
                      onRemove={() => removeVHostRoute(vhIdx, rIdx)}
                    />
                  ))}
                </div>
                <Button
                  size="sm"
                  variant="secondary"
                  className="mt-2"
                  onClick={() => addVHostRoute(vhIdx)}
                >
                  <Plus className="h-3.5 w-3.5" />
                  Add Route
                </Button>
              </div>
            </div>
          ))}

          <Button variant="secondary" onClick={addVHost}>
            <Plus className="h-4 w-4" />
            Add Virtual Host
          </Button>
        </div>
      </Section>

      {/* ==================== Default Routes ==================== */}
      <Section title="Default Routes" defaultOpen>
        <div className="space-y-2">
          {(routing.routes || []).map((route, idx) => (
            <RouteRow
              key={idx}
              route={route}
              upstreamNames={upstreamNames}
              onChange={(patch) => updateDefaultRoute(idx, patch)}
              onRemove={() => removeDefaultRoute(idx)}
            />
          ))}
          <Button size="sm" variant="secondary" onClick={addDefaultRoute}>
            <Plus className="h-3.5 w-3.5" />
            Add Route
          </Button>
        </div>
      </Section>

      {/* Save bar */}
      <div className="fixed bottom-0 left-0 right-0 z-50 border-t border-border bg-card/95 backdrop-blur-sm">
        <div className="mx-auto flex max-w-5xl items-center justify-end px-6 py-3">
          <Button onClick={handleSave} disabled={saving}>
            {saving ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Route className="h-4 w-4" />
            )}
            Save &amp; Rebuild Proxy
          </Button>
        </div>
      </div>

      </>}
    </div>
  )
}

/* ---------- Route Row Component ---------- */

function RouteRow({
  route,
  upstreamNames,
  onChange,
  onRemove,
}: {
  route: RouteConfig
  upstreamNames: string[]
  onChange: (patch: Partial<RouteConfig>) => void
  onRemove: () => void
}) {
  return (
    <div className="flex items-center gap-2">
      <Input
        placeholder="/path"
        value={route.path}
        onChange={(e) => onChange({ path: e.target.value })}
        className="font-mono w-40"
      />
      <span className="text-xs text-muted-foreground shrink-0">-&gt;</span>
      <Select
        value={route.upstream}
        onChange={(e) => onChange({ upstream: e.target.value })}
        className={cn('w-44', !route.upstream && 'text-muted-foreground')}
      >
        <SelectOption value="">Select upstream</SelectOption>
        {upstreamNames.map((name) => (
          <SelectOption key={name} value={name}>
            {name}
          </SelectOption>
        ))}
      </Select>
      <Button size="icon" variant="ghost" onClick={onRemove}>
        <Trash2 className="h-3.5 w-3.5 text-muted-foreground hover:text-destructive" />
      </Button>
    </div>
  )
}
