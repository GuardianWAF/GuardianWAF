import { Check, X, Minus } from 'lucide-react'
import { cn } from '@/lib/utils'

type FeatureStatus = 'yes' | 'no' | 'partial'

interface ComparisonRow {
  feature: string
  guardianwaf: FeatureStatus
  safeline: FeatureStatus
  coraza: FeatureStatus
  modsecurity: FeatureStatus
  naxsi: FeatureStatus
}

const rows: ComparisonRow[] = [
  { feature: 'Zero Dependencies', guardianwaf: 'yes', safeline: 'no', coraza: 'no', modsecurity: 'no', naxsi: 'no' },
  { feature: 'Single Binary', guardianwaf: 'yes', safeline: 'no', coraza: 'partial', modsecurity: 'no', naxsi: 'no' },
  { feature: 'Multi-Domain Routing', guardianwaf: 'yes', safeline: 'no', coraza: 'no', modsecurity: 'no', naxsi: 'no' },
  { feature: 'Load Balancing (4 strategies)', guardianwaf: 'yes', safeline: 'no', coraza: 'no', modsecurity: 'no', naxsi: 'no' },
  { feature: 'JS Challenge (PoW)', guardianwaf: 'yes', safeline: 'no', coraza: 'no', modsecurity: 'no', naxsi: 'no' },
  { feature: 'Auto TLS + ACME', guardianwaf: 'yes', safeline: 'yes', coraza: 'no', modsecurity: 'no', naxsi: 'no' },
  { feature: 'Circuit Breaker', guardianwaf: 'yes', safeline: 'no', coraza: 'no', modsecurity: 'no', naxsi: 'no' },
  { feature: 'Dashboard + Config Editor', guardianwaf: 'yes', safeline: 'yes', coraza: 'no', modsecurity: 'no', naxsi: 'no' },
  { feature: 'Embeddable Library', guardianwaf: 'yes', safeline: 'no', coraza: 'yes', modsecurity: 'no', naxsi: 'no' },
  { feature: 'MCP / AI Integration', guardianwaf: 'yes', safeline: 'no', coraza: 'no', modsecurity: 'no', naxsi: 'no' },
  { feature: 'Bot Detection (JA3 + UA + Behavior)', guardianwaf: 'yes', safeline: 'yes', coraza: 'partial', modsecurity: 'partial', naxsi: 'no' },
  { feature: 'Threat Intelligence Feeds', guardianwaf: 'yes', safeline: 'no', coraza: 'no', modsecurity: 'partial', naxsi: 'no' },
  { feature: 'CORS Security Layer', guardianwaf: 'yes', safeline: 'no', coraza: 'no', modsecurity: 'no', naxsi: 'no' },
  { feature: 'ATO Protection', guardianwaf: 'yes', safeline: 'no', coraza: 'no', modsecurity: 'no', naxsi: 'no' },
  { feature: 'API Security (JWT + API Keys)', guardianwaf: 'yes', safeline: 'no', coraza: 'no', modsecurity: 'no', naxsi: 'no' },
  { feature: '<1ms p99 Latency', guardianwaf: 'yes', safeline: 'no', coraza: 'partial', modsecurity: 'no', naxsi: 'yes' },
]

const products = [
  { key: 'guardianwaf' as const, label: 'GuardianWAF', highlight: true },
  { key: 'safeline' as const, label: 'SafeLine' },
  { key: 'coraza' as const, label: 'Coraza' },
  { key: 'modsecurity' as const, label: 'ModSecurity' },
  { key: 'naxsi' as const, label: 'NAXSI' },
]

function StatusIcon({ status }: { status: FeatureStatus }) {
  switch (status) {
    case 'yes':
      return <Check className="h-4 w-4 text-success mx-auto" aria-label="Yes" />
    case 'no':
      return <X className="h-4 w-4 text-destructive/60 mx-auto" aria-label="No" />
    case 'partial':
      return <Minus className="h-4 w-4 text-warning mx-auto" aria-label="Partial" />
  }
}

export function Comparison() {
  return (
    <section id="comparison" className="py-20 sm:py-28" aria-labelledby="comparison-heading">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12 sm:mb-16">
          <h2 id="comparison-heading" className="text-3xl sm:text-4xl font-bold text-foreground">
            How GuardianWAF compares
          </h2>
          <p className="mt-4 text-lg text-muted max-w-2xl mx-auto">
            A feature-by-feature comparison with popular open-source WAF solutions.
          </p>
        </div>

        <div className="overflow-x-auto rounded-xl border border-border">
          <table className="w-full text-sm" role="table">
            <thead>
              <tr className="border-b border-border bg-card">
                <th className="text-left px-4 py-3 font-medium text-muted" scope="col">Feature</th>
                {products.map((p) => (
                  <th
                    key={p.key}
                    className={cn(
                      'px-4 py-3 font-medium text-center min-w-[100px]',
                      p.highlight ? 'text-accent bg-accent/5' : 'text-muted'
                    )}
                    scope="col"
                  >
                    {p.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                <tr
                  key={row.feature}
                  className={cn(
                    'border-b border-border last:border-0 transition-colors hover:bg-card/50',
                    i % 2 === 0 ? 'bg-transparent' : 'bg-card/30'
                  )}
                >
                  <td className="px-4 py-3 font-medium text-foreground">{row.feature}</td>
                  {products.map((p) => (
                    <td
                      key={p.key}
                      className={cn(
                        'px-4 py-3 text-center',
                        p.highlight ? 'bg-accent/5' : ''
                      )}
                    >
                      <StatusIcon status={row[p.key]} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  )
}
