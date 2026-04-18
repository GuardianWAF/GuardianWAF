import { useState, useEffect, useCallback } from 'react'
import { Download, FileCheck, Shield, AlertTriangle, CheckCircle2, XCircle, MinusCircle, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { api, ComplianceReport, ComplianceControlsResponse, AuditChainResponse } from '@/lib/api'
import { useToast } from '@/components/ui/toast'
import { cn } from '@/lib/utils'

const FRAMEWORK_LABELS: Record<string, string> = {
  pci_dss: 'PCI DSS v4.0',
  gdpr: 'GDPR / KVKK',
  soc2: 'SOC 2 Type II',
  iso27001: 'ISO 27001',
}

export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState<string[]>([])
  const [activeFramework, setActiveFramework] = useState('')
  const [report, setReport] = useState<ComplianceReport | null>(null)
  const [controls, setControls] = useState<ComplianceControlsResponse | null>(null)
  const [auditChain, setAuditChain] = useState<AuditChainResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { toast } = useToast()

  const fetchControls = useCallback(async () => {
    try {
      const res = await api.getComplianceControls()
      setControls(res)
      setFrameworks(res.frameworks)
      if (res.frameworks.length > 0 && !activeFramework) {
        setActiveFramework(res.frameworks[0])
      }
    } catch {
      // compliance may not be configured
    }
  }, [activeFramework])

  const fetchAuditChain = useCallback(async () => {
    try {
      const res = await api.getAuditChain()
      setAuditChain({ ...res, valid: res.valid ?? 0, length: res.length ?? 0, errors: res.errors ?? [], integrity: res.integrity ?? true })
    } catch {
      // audit chain may not be available
    }
  }, [])

  useEffect(() => {
    ;(async () => {
      try {
        await fetchControls()
        await fetchAuditChain()
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Failed to load compliance data')
      } finally {
        setLoading(false)
      }
    })()
  }, [fetchControls, fetchAuditChain])

  const generateReport = async () => {
    if (!activeFramework) return
    setGenerating(true)
    setError(null)
    try {
      const now = new Date()
      const from = new Date(now.getFullYear(), now.getMonth(), 1)
      const res = await api.getComplianceReport(activeFramework, {
        from: from.toISOString(),
        to: now.toISOString(),
      })
      setReport(res)
      toast({ title: 'Report generated', description: `${FRAMEWORK_LABELS[activeFramework] || activeFramework} report ready` })
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to generate report')
    } finally {
      setGenerating(false)
    }
  }

  const downloadJSON = () => {
    if (!report) return
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${report.report_id}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const downloadCSV = () => {
    if (!report) return
    const lines = ['control_id,control_name,status']
    for (const c of report.controls) {
      lines.push(`"${c.id}","${c.name}","${c.status}"`)
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${report.report_id}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  if (loading) {
    return (
      <div className="flex min-h-[50vh] items-center justify-center">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-accent border-t-transparent" />
      </div>
    )
  }

  if (error && frameworks.length === 0) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold">Compliance</h1>
        <Card>
          <CardContent className="py-12 text-center">
            <Shield className="mx-auto h-12 w-12 text-muted-foreground/50" />
            <p className="mt-4 text-sm text-muted-foreground">
              Compliance reporting is not configured.
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              Enable it in the WAF config under <code className="text-foreground">compliance.enabled: true</code>
            </p>
          </CardContent>
        </Card>
      </div>
    )
  }

  const statusIcon = (status: string) => {
    switch (status) {
      case 'passing':
        return <CheckCircle2 className="h-4 w-4 text-green-500" />
      case 'failing':
        return <XCircle className="h-4 w-4 text-red-500" />
      case 'not_applicable':
        return <MinusCircle className="h-4 w-4 text-muted-foreground" />
      default:
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />
    }
  }

  const statusBadge = (status: string) => {
    const variants: Record<string, 'default' | 'destructive' | 'secondary' | 'outline'> = {
      passing: 'default',
      failing: 'destructive',
      not_applicable: 'secondary',
      no_evidence: 'outline',
    }
    return <Badge variant={variants[status] || 'outline'}>{status.replace('_', ' ')}</Badge>
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Compliance</h1>
        <div className="flex items-center gap-2">
          <Button onClick={generateReport} disabled={!activeFramework || generating} size="sm">
            {generating ? (
              <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <FileCheck className="mr-2 h-4 w-4" />
            )}
            Generate Report
          </Button>
          {report && (
            <>
              <Button onClick={downloadJSON} variant="outline" size="sm">
                <Download className="mr-2 h-4 w-4" />
                JSON
              </Button>
              <Button onClick={downloadCSV} variant="outline" size="sm">
                <Download className="mr-2 h-4 w-4" />
                CSV
              </Button>
            </>
          )}
        </div>
      </div>

      {error && (
        <div className="rounded-md border border-destructive/50 bg-destructive/5 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      )}

      {/* Framework Tabs */}
      <div className="flex gap-2">
        {frameworks.map((fw) => (
          <button
            key={fw}
            onClick={() => { setActiveFramework(fw); setReport(null) }}
            className={cn(
              'rounded-md px-3 py-1.5 text-sm font-medium transition-colors',
              activeFramework === fw
                ? 'bg-accent text-accent-foreground'
                : 'text-muted-foreground hover:bg-muted hover:text-foreground',
            )}
          >
            {FRAMEWORK_LABELS[fw] || fw}
          </button>
        ))}
      </div>

      {/* Report Summary */}
      {report && (
        <div className="grid grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold">{report.summary.controls_passing}</div>
              <p className="text-xs text-muted-foreground">Passing</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold text-red-500">{report.summary.controls_failing}</div>
              <p className="text-xs text-muted-foreground">Failing</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="text-2xl font-bold text-muted-foreground">{report.summary.controls_not_applicable}</div>
              <p className="text-xs text-muted-foreground">Not Applicable</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                {statusIcon(report.summary.overall_status)}
                <span className="text-lg font-bold capitalize">{report.summary.overall_status}</span>
              </div>
              <p className="text-xs text-muted-foreground">Overall Status</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Control Status Table */}
      <Card>
        <CardHeader>
          <CardTitle>Control Status</CardTitle>
          <CardDescription>
            {activeFramework
              ? `${FRAMEWORK_LABELS[activeFramework] || activeFramework} requirements mapped to WAF capabilities`
              : 'Select a framework to view controls'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="py-2 text-left font-medium text-muted-foreground">Status</th>
                <th className="py-2 text-left font-medium text-muted-foreground">Control ID</th>
                <th className="py-2 text-left font-medium text-muted-foreground">Name</th>
                <th className="py-2 text-left font-medium text-muted-foreground">Evidence</th>
              </tr>
            </thead>
            <tbody>
              {report ? (
                report.controls.map((ctrl) => (
                  <tr key={ctrl.id} className="border-b border-border/50 hover:bg-muted/30">
                    <td className="py-2.5 pr-3">
                      <span className="flex items-center gap-1.5">
                        {statusIcon(ctrl.status)}
                        {statusBadge(ctrl.status)}
                      </span>
                    </td>
                    <td className="py-2.5 pr-3 font-mono text-xs">{ctrl.id}</td>
                    <td className="py-2.5 pr-3">{ctrl.name}</td>
                    <td className="py-2.5 text-xs text-muted-foreground">
                      {ctrl.evidence ? Object.keys(ctrl.evidence).join(', ') : '—'}
                    </td>
                  </tr>
                ))
              ) : controls ? (
                controls.controls
                  .filter((c) => c.frameworks.includes(activeFramework))
                  .map((ctrl) => (
                    <tr key={ctrl.id} className="border-b border-border/50 hover:bg-muted/30">
                      <td className="py-2.5 pr-3">
                        <Badge variant="outline">registered</Badge>
                      </td>
                      <td className="py-2.5 pr-3 font-mono text-xs">{ctrl.id}</td>
                      <td className="py-2.5 pr-3">{ctrl.name}</td>
                      <td className="py-2.5 text-xs text-muted-foreground">
                        {ctrl.evidence.map((e: { type: string }) => e.type).join(', ')}
                      </td>
                    </tr>
                  ))
              ) : (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-muted-foreground">
                    No controls found. Generate a report to evaluate controls.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>

      {/* Audit Chain Status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Audit Trail
          </CardTitle>
          <CardDescription>Hash-chained audit trail for tamper evidence verification</CardDescription>
        </CardHeader>
        <CardContent>
          {auditChain ? (
            <div className="grid grid-cols-3 gap-4">
              <div>
                <div className="text-2xl font-bold">{auditChain.length}</div>
                <p className="text-xs text-muted-foreground">Chain entries</p>
              </div>
              <div>
                <div className={cn('text-2xl font-bold', auditChain.integrity ? 'text-green-500' : 'text-red-500')}>
                  {auditChain.valid}/{auditChain.length}
                </div>
                <p className="text-xs text-muted-foreground">Valid entries</p>
              </div>
              <div>
                <div className={cn('text-2xl font-bold', auditChain.integrity ? 'text-green-500' : 'text-red-500')}>
                  {auditChain.integrity ? 'Intact' : `${auditChain.errors?.length ?? 0} errors`}
                </div>
                <p className="text-xs text-muted-foreground">Integrity</p>
              </div>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">Audit trail not available or not configured.</p>
          )}
          {report?.chain_hash && (
            <div className="mt-4 rounded-md bg-muted/50 p-3">
              <p className="text-xs text-muted-foreground">Report chain hash</p>
              <p className="font-mono text-xs break-all">{report.chain_hash}</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
