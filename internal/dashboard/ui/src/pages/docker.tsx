import { useCallback, useEffect, useState } from 'react'
import { Activity, Container, RefreshCw, Server, Tag, Waypoints } from 'lucide-react'
import { api } from '@/lib/api'
import type { DockerEvent, DockerService } from '@/lib/api'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { useToast } from '@/components/ui/toast'
import { cn } from '@/lib/utils'

export default function DockerPage() {
  const [enabled, setEnabled] = useState(false)
  const [services, setServices] = useState<DockerService[]>([])
  const [containers, setContainers] = useState<DockerService[]>([])
  const [events, setEvents] = useState<DockerEvent[]>([])
  const [loading, setLoading] = useState(true)
  const { toast } = useToast()

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [serviceData, containerData, eventData] = await Promise.all([
        api.getDockerServices(),
        api.getDockerContainers(),
        api.getDockerEvents(20),
      ])
      setEnabled(Boolean(serviceData.enabled || containerData.enabled || eventData.enabled))
      setServices(serviceData.services ?? [])
      setContainers(containerData.containers ?? [])
      setEvents(eventData.events ?? [])
    } catch {
      toast({ title: 'Failed to load Docker data', variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }, [toast])

  useEffect(() => {
    load()
  }, [load])

  const running = containers.filter((container) => container.status === 'running').length

  return (
    <div className="space-y-6 docker-page">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <Container className="h-5 w-5 text-accent" />
          <div>
            <h1 className="text-2xl font-semibold">Docker Discovery</h1>
            <p className="text-sm text-muted-foreground">
              Container labels discovered for dynamic routing.
            </p>
          </div>
        </div>
        <Button variant="outline" onClick={load} disabled={loading}>
          <RefreshCw className={cn('mr-2 h-4 w-4', loading && 'animate-spin')} />
          Refresh
        </Button>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Metric icon={Activity} label="Status" value={enabled ? 'Enabled' : 'Disabled'} tone={enabled ? 'success' : 'muted'} />
        <Metric icon={Server} label="Containers" value={String(containers.length)} />
        <Metric icon={Waypoints} label="Services" value={String(services.length)} />
        <Metric icon={Container} label="Running" value={String(running)} />
      </div>

      {!enabled && (
        <section className="rounded-lg border border-border bg-card p-5">
          <div className="flex items-start gap-3">
            <Container className="mt-0.5 h-5 w-5 text-muted-foreground" />
            <div>
              <h2 className="text-sm font-semibold">Docker integration is disabled</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                Enable docker discovery in the GuardianWAF config and mount the Docker socket to populate this page.
              </p>
            </div>
          </div>
        </section>
      )}

      <Card>
        <CardHeader>
          <h2 className="font-semibold leading-none tracking-tight">Discovered Services</h2>
        </CardHeader>
        <CardContent>
          <ServiceTable services={services} loading={loading} emptyText="No Docker services discovered." />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <h2 className="font-semibold leading-none tracking-tight">Containers</h2>
        </CardHeader>
        <CardContent>
          <ServiceTable services={containers} loading={loading} emptyText="No Docker containers discovered." />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <h2 className="font-semibold leading-none tracking-tight">Recent Events</h2>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="py-8 text-center text-sm text-muted-foreground">Loading Docker events...</div>
          ) : events.length === 0 ? (
            <div className="py-8 text-center text-sm text-muted-foreground">No recent Docker events.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <caption className="sr-only">Recent Docker events with time, container, action, image, and message columns</caption>
                <thead>
                  <tr className="border-b border-border">
                    <th scope="col" className="px-3 py-2 text-left font-medium text-muted-foreground">Time</th>
                    <th scope="col" className="px-3 py-2 text-left font-medium text-muted-foreground">Container</th>
                    <th scope="col" className="px-3 py-2 text-left font-medium text-muted-foreground">Action</th>
                    <th scope="col" className="px-3 py-2 text-left font-medium text-muted-foreground">Image</th>
                    <th scope="col" className="px-3 py-2 text-left font-medium text-muted-foreground">Message</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((event, index) => (
                    <tr key={event.id || index} className="border-b border-border/60">
                      <td className="px-3 py-2 text-muted-foreground">{formatEventTime(event)}</td>
                      <td className="px-3 py-2 font-mono text-xs">{String(event.container || event.id || '-')}</td>
                      <td className="px-3 py-2">{String(event.action || event.status || '-')}</td>
                      <td className="px-3 py-2 text-muted-foreground">{String(event.image || '-')}</td>
                      <td className="px-3 py-2 text-muted-foreground">{String(event.message || '-')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function Metric({ icon: Icon, label, value, tone = 'default' }: { icon: typeof Activity; label: string; value: string; tone?: 'default' | 'success' | 'muted' }) {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="mb-2 flex items-center gap-2 text-xs text-muted-foreground">
        <Icon className="h-4 w-4" />
        {label}
      </div>
      <div className={cn('text-2xl font-semibold', tone === 'success' && 'text-green-500', tone === 'muted' && 'text-muted-foreground')}>
        {value}
      </div>
    </div>
  )
}

function ServiceTable({ services, loading, emptyText }: { services: DockerService[]; loading: boolean; emptyText: string }) {
  if (loading) {
    return <div className="py-8 text-center text-sm text-muted-foreground">Loading Docker services...</div>
  }
  if (services.length === 0) {
    return <div className="empty-state py-8 text-center text-sm text-muted-foreground">{emptyText}</div>
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <caption className="sr-only">Docker services with container, image, target, host, upstream, health path, and status columns</caption>
        <thead>
          <tr className="border-b border-border">
            <th scope="col" className="px-3 py-2 text-left font-medium text-muted-foreground">Container</th>
            <th scope="col" className="px-3 py-2 text-left font-medium text-muted-foreground">Target</th>
            <th scope="col" className="px-3 py-2 text-left font-medium text-muted-foreground">Route</th>
            <th scope="col" className="px-3 py-2 text-left font-medium text-muted-foreground">Upstream</th>
            <th scope="col" className="px-3 py-2 text-left font-medium text-muted-foreground">Health</th>
            <th scope="col" className="px-3 py-2 text-left font-medium text-muted-foreground">Status</th>
          </tr>
        </thead>
        <tbody>
          {services.map((service, index) => (
            <tr key={`${service.container_name}-${service.target}-${index}`} className="border-b border-border/60">
              <td className="px-3 py-2">
                <div className="flex items-center gap-2">
                  <Container className="h-4 w-4 text-accent" />
                  <div>
                    <div className="font-medium">{service.container_name || service.name || '-'}</div>
                    <div className="text-xs text-muted-foreground">{service.image || '-'}</div>
                  </div>
                </div>
              </td>
              <td className="px-3 py-2 font-mono text-xs">{service.target || '-'}</td>
              <td className="px-3 py-2">
                {service.host ? (
                  <span className="font-mono text-xs">{service.host}{service.path && service.path !== '/' ? service.path : ''}</span>
                ) : (
                  <span className="text-muted-foreground">-</span>
                )}
              </td>
              <td className="px-3 py-2">
                <div className="flex items-center gap-2">
                  <Tag className="h-3.5 w-3.5 text-muted-foreground" />
                  <span>{service.upstream || '-'}</span>
                  {service.weight > 0 && <span className="text-xs text-muted-foreground">w:{service.weight}</span>}
                </div>
              </td>
              <td className="px-3 py-2 font-mono text-xs text-muted-foreground">{service.health_path || '-'}</td>
              <td className="px-3 py-2">
                <Badge variant={service.status === 'running' ? 'default' : 'outline'}>{service.status || 'unknown'}</Badge>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function formatEventTime(event: DockerEvent) {
  const raw = event.timestamp || event.time
  if (!raw) return '-'
  const date = new Date(String(raw))
  if (Number.isNaN(date.getTime())) return String(raw)
  return date.toLocaleString()
}
