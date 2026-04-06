import { useState, useEffect, useCallback } from 'react'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import { Section } from '@/components/config/section'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Loader2, RefreshCw, AlertTriangle, CheckCircle2, XCircle, KeyRound, Globe, Calendar, Shield } from 'lucide-react'

interface CertInfo {
  domain: string
  dns_names: string[]
  not_after: string
  days_left: number
  issuer_cn: string
  needs_renewal: boolean
  is_wildcard: boolean
}

interface CertStatus {
  enabled: boolean
  cache_dir: string
  domains: string[][]
  certs: CertInfo[]
}

export default function SSLPage() {
  const [certStatus, setCertStatus] = useState<CertStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [refreshing, setRefreshing] = useState(false)

  const fetchCerts = useCallback(async () => {
    try {
      const data = await api.getSSL()
      setCertStatus(data)
      setError(null)
    } catch (err) {
      setError('Failed to load SSL certificates')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchCerts() }, [fetchCerts])

  const handleRefresh = async () => {
    setRefreshing(true)
    await fetchCerts()
    setRefreshing(false)
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (error || !certStatus) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-4">
        <AlertTriangle className="h-8 w-8 text-destructive" />
        <p className="text-sm text-muted-foreground">{error || 'No SSL data available'}</p>
      </div>
    )
  }

  const expiringCerts = certStatus.certs?.filter(c => c.needs_renewal) || []

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">SSL / TLS</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage TLS certificates and ACME auto-renewal
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
          <RefreshCw className={cn('h-4 w-4 mr-2', refreshing && 'animate-spin')} />
          Refresh
        </Button>
      </div>

      {/* ACME Status */}
      <Section title="ACME / Let's Encrypt" defaultOpen>
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            {certStatus.enabled ? (
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5 text-green-500" />
                <span className="text-sm">Auto-certificate management enabled</span>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <XCircle className="h-5 w-5 text-muted-foreground" />
                <span className="text-sm text-muted-foreground">ACME disabled</span>
              </div>
            )}
          </div>

          {certStatus.cache_dir && (
            <div className="text-xs text-muted-foreground font-mono bg-muted p-2 rounded">
              Cache: {certStatus.cache_dir}
            </div>
          )}

          {certStatus.domains && certStatus.domains.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                Registered Domain Groups
              </h4>
              <div className="flex flex-wrap gap-2">
                {certStatus.domains.map((group, i) => (
                  <Badge key={i} variant="secondary">
                    {group.join(', ')}
                  </Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      </Section>

      {/* Expiring Soon Alert */}
      {expiringCerts.length > 0 && (
        <Section title="Expiring Soon" defaultOpen>
          <div className="space-y-3">
            {expiringCerts.map((cert) => (
              <div
                key={cert.domain}
                className="flex items-center justify-between p-3 rounded-md border border-orange-500/30 bg-orange-500/5"
              >
                <div className="flex items-center gap-3">
                  <AlertTriangle className="h-5 w-5 text-orange-500" />
                  <div>
                    <p className="text-sm font-medium">{cert.domain}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <Calendar className="h-3 w-3 text-muted-foreground" />
                      <span className="text-xs text-muted-foreground">
                        Expires: {new Date(cert.not_after).toLocaleDateString()}
                      </span>
                      <Badge variant="destructive" className="text-xs">
                        {cert.days_left} days left
                      </Badge>
                    </div>
                  </div>
                </div>
                <Button size="sm" variant="outline">
                  Renew Now
                </Button>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* All Certificates */}
      <Section title="Certificates" defaultOpen>
        {!certStatus.certs || certStatus.certs.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 gap-3 text-muted-foreground">
            <KeyRound className="h-8 w-8" />
            <p className="text-sm">No certificates configured</p>
            <p className="text-xs">Enable ACME or add certificates in Config</p>
          </div>
        ) : (
          <div className="space-y-4">
            {certStatus.certs.map((cert) => (
              <div
                key={cert.domain}
                className={cn(
                  'rounded-md border p-4',
                  cert.needs_renewal
                    ? 'border-orange-500/30 bg-orange-500/5'
                    : 'border-border bg-card'
                )}
              >
                {/* Header row */}
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <Globe className="h-5 w-5 text-muted-foreground" />
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{cert.domain}</span>
                        {cert.is_wildcard && (
                          <Badge variant="secondary" className="text-xs">Wildcard</Badge>
                        )}
                      </div>
                      {cert.dns_names && cert.dns_names.length > 1 && (
                        <p className="text-xs text-muted-foreground mt-0.5">
                          Also: {cert.dns_names.filter(d => d !== cert.domain).join(', ')}
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {cert.needs_renewal ? (
                      <Badge variant="destructive">Expiring</Badge>
                    ) : (
                      <Badge variant="outline" className="text-green-500 border-green-500">
                        Valid
                      </Badge>
                    )}
                  </div>
                </div>

                {/* Details grid */}
                <div className="grid grid-cols-3 gap-4 text-sm">
                  <div>
                    <p className="text-xs text-muted-foreground">Issuer</p>
                    <p className="font-mono text-xs">{cert.issuer_cn}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Expires</p>
                    <p className="text-xs">
                      {new Date(cert.not_after).toLocaleDateString()}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Days Remaining</p>
                    <p className={cn(
                      'text-xs font-medium',
                      cert.days_left <= 30 ? 'text-orange-500' : 'text-green-500'
                    )}>
                      {cert.days_left} days
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>

      {/* TLS Configuration */}
      <Section title="TLS Settings">
        <div className="space-y-4">
          <div className="text-xs text-muted-foreground">
            TLS configuration is managed via the WAF Config page.
          </div>
          <Button variant="outline" onClick={() => window.location.href = '/config'}>
            <Shield className="h-4 w-4 mr-2" />
            Open WAF Config
          </Button>
        </div>
      </Section>
    </div>
  )
}