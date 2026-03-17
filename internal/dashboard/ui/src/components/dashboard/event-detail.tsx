import { X } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { WafEvent } from '@/lib/api'

interface EventDetailProps {
  event: WafEvent
  onClose: () => void
}

const severityColors: Record<string, string> = {
  critical: 'bg-destructive/20 text-destructive',
  high: 'bg-orange/20 text-orange',
  medium: 'bg-warning/20 text-warning',
  low: 'bg-accent/20 text-accent',
  info: 'bg-muted/20 text-muted',
}

export function EventDetail({ event, onClose }: EventDetailProps) {
  return (
    <>
      {/* Overlay */}
      <div className="fixed inset-0 bg-black/50 z-40" onClick={onClose} />

      {/* Sheet */}
      <div className="fixed right-0 top-0 bottom-0 w-full max-w-xl bg-card border-l border-border z-50 overflow-y-auto animate-in slide-in-from-right">
        {/* Header */}
        <div className="sticky top-0 bg-card border-b border-border px-6 py-4 flex items-center justify-between">
          <div>
            <h2 className="font-semibold">Event Detail</h2>
            <p className="text-xs text-muted mt-0.5">{event.request_id}</p>
          </div>
          <button onClick={onClose} className="rounded-md p-1.5 hover:bg-background transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Request Info */}
          <Section title="Request">
            <Grid>
              <Field label="Method" value={event.method} mono />
              <Field label="Path" value={event.path} mono />
              <Field label="Query" value={event.query || '-'} mono />
              <Field label="Client IP" value={event.client_ip} mono />
              <Field label="Host" value={event.host || '-'} />
              <Field label="Status Code" value={String(event.status_code)} />
            </Grid>
          </Section>

          {/* Action & Score */}
          <Section title="Decision">
            <Grid>
              <Field label="Action" value={event.action.toUpperCase()} highlight={event.action} />
              <Field label="Threat Score" value={`${event.score}/100`} />
              <Field label="Duration" value={`${(event.duration_ns / 1_000_000).toFixed(2)} ms`} />
            </Grid>
          </Section>

          {/* Client Info */}
          <Section title="Client">
            <Grid>
              <Field label="Browser" value={`${event.browser || '-'} ${event.browser_version || ''}`} />
              <Field label="OS" value={event.os || '-'} />
              <Field label="Device" value={event.device_type || 'unknown'} />
              <Field label="Bot" value={event.is_bot ? 'Yes' : 'No'} />
              <Field label="Content-Type" value={event.content_type || '-'} />
              <Field label="Referer" value={event.referer || '-'} />
            </Grid>
          </Section>

          {/* User Agent */}
          <Section title="User Agent">
            <p className="text-xs font-mono text-muted-foreground break-all bg-background rounded-md p-3">
              {event.user_agent || '-'}
            </p>
          </Section>

          {/* Findings */}
          <Section title={`Findings (${event.findings?.length || 0})`}>
            {(!event.findings || event.findings.length === 0) ? (
              <p className="text-xs text-muted">No findings for this request</p>
            ) : (
              <div className="space-y-2">
                {event.findings.map((f, i) => (
                  <div key={i} className="rounded-md border border-border bg-background p-3">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-semibold">{f.detector}</span>
                        <span className={cn('text-[10px] px-1.5 py-0.5 rounded font-medium uppercase', severityColors[f.severity] || severityColors.info)}>
                          {f.severity}
                        </span>
                      </div>
                      <span className="text-xs font-bold text-foreground">+{f.score}</span>
                    </div>
                    <p className="text-xs text-muted-foreground">{f.description}</p>
                    {f.matched_value && (
                      <div className="mt-2 rounded bg-card px-2 py-1">
                        <span className="text-[10px] text-muted">Matched: </span>
                        <span className="text-[10px] font-mono text-destructive break-all">{f.matched_value}</span>
                      </div>
                    )}
                    <div className="flex gap-3 mt-2 text-[10px] text-muted">
                      <span>Location: {f.location}</span>
                      <span>Confidence: {(f.confidence * 100).toFixed(0)}%</span>
                      <span>Category: {f.category}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Section>
        </div>
      </div>
    </>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-xs font-semibold text-muted uppercase tracking-wider mb-3">{title}</h3>
      {children}
    </div>
  )
}

function Grid({ children }: { children: React.ReactNode }) {
  return <div className="grid grid-cols-2 gap-x-4 gap-y-2">{children}</div>
}

function Field({ label, value, mono, highlight }: { label: string; value: string; mono?: boolean; highlight?: string }) {
  const actionColors: Record<string, string> = {
    block: 'text-destructive font-bold',
    challenge: 'text-orange font-bold',
    log: 'text-warning font-bold',
    pass: 'text-success font-bold',
  }

  return (
    <div>
      <div className="text-[10px] text-muted uppercase tracking-wider">{label}</div>
      <div className={cn('text-sm', mono && 'font-mono', highlight && actionColors[highlight])}>
        {value}
      </div>
    </div>
  )
}
