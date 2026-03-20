import { useState, useEffect, useCallback, useMemo } from 'react'
import { Section } from '@/components/config/section'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import {
  Brain, Loader2, CheckCircle2, XCircle, Zap, DollarSign,
  Shield, Eye, Ban, Clock, Sparkles, Search,
  ChevronDown, Lock, Activity, ExternalLink, Cpu, RefreshCw,
} from 'lucide-react'
import { cn } from '@/lib/utils'

// --- Types ---

interface ProviderSummary {
  id: string; name: string; api: string; doc: string; model_count: number
  models: ModelSummary[]
}

interface ModelSummary {
  id: string; name: string; family: string; reasoning: boolean; tool_call: boolean
  cost_input_per_m: number; cost_output_per_m: number; context_window: number; max_output: number
}

interface AIConfig {
  enabled: boolean; provider_id: string; provider_name: string; model_id: string
  model_name: string; base_url: string; api_key_set: boolean; api_key_mask: string
}

interface AIStats {
  enabled: boolean; tokens_used_hour: number; tokens_used_day: number
  requests_hour: number; requests_day: number; total_tokens_used: number
  total_requests: number; total_cost_usd: number; blocks_triggered: number; monitors_triggered: number
}

interface Verdict { ip: string; action: string; reason: string; confidence: number }

interface AnalysisResult {
  id: string; timestamp: string; event_count: number; verdicts: Verdict[]
  summary: string; threats_detected: string[]; tokens_used: number
  cost_usd: number; duration_ms: number; model: string; error?: string
}

// --- API ---

const aiApi = {
  getProviders: () => fetch('/api/v1/ai/providers').then(r => r.json()),
  getConfig: () => fetch('/api/v1/ai/config').then(r => r.json()),
  setConfig: (data: Record<string, string>) =>
    fetch('/api/v1/ai/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) }).then(r => r.json()),
  getHistory: (limit = 20) => fetch(`/api/v1/ai/history?limit=${limit}`).then(r => r.json()),
  getStats: () => fetch('/api/v1/ai/stats').then(r => r.json()),
  analyze: (limit = 20) => fetch(`/api/v1/ai/analyze?limit=${limit}`, { method: 'POST' }).then(r => r.json()),
  test: () => fetch('/api/v1/ai/test', { method: 'POST' }).then(r => r.json()),
}

// --- Page ---

export default function AIPage() {
  const [providers, setProviders] = useState<ProviderSummary[]>([])
  const [config, setConfig] = useState<AIConfig | null>(null)
  const [stats, setStats] = useState<AIStats | null>(null)
  const [history, setHistory] = useState<AnalysisResult[]>([])
  const [loading, setLoading] = useState(true)
  const [loadingProviders, setLoadingProviders] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  // Provider selection
  const [selectedProvider, setSelectedProvider] = useState<ProviderSummary | null>(null)
  const [selectedModel, setSelectedModel] = useState<ModelSummary | null>(null)
  const [apiKey, setApiKey] = useState('')
  const [providerSearch, setProviderSearch] = useState('')
  const [modelSearch, setModelSearch] = useState('')
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ status: string; message: string } | null>(null)
  const [saving, setSaving] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [analyzeResult, setAnalyzeResult] = useState<AnalysisResult | null>(null)

  const refresh = useCallback(() => {
    Promise.all([
      aiApi.getConfig().catch(() => null),
      aiApi.getStats().catch(() => null),
      aiApi.getHistory().catch(() => ({ history: [] })),
    ]).then(([cfg, st, hist]) => {
      if (cfg) setConfig(cfg)
      if (st) setStats(st)
      if (hist?.history) setHistory(hist.history)
      setLoading(false)
    })
  }, [])

  const fetchProviders = useCallback(() => {
    setLoadingProviders(true)
    aiApi.getProviders().then(data => {
      setProviders(data.providers || [])
    }).catch(() => {}).finally(() => setLoadingProviders(false))
  }, [])

  useEffect(() => { refresh(); fetchProviders() }, [refresh, fetchProviders])

  // Filter providers
  const filteredProviders = useMemo(() => {
    if (!providerSearch) return providers
    const q = providerSearch.toLowerCase()
    return providers.filter(p =>
      p.name.toLowerCase().includes(q) || p.id.toLowerCase().includes(q)
    )
  }, [providers, providerSearch])

  // Filter models of selected provider
  const filteredModels = useMemo(() => {
    if (!selectedProvider) return []
    const models = selectedProvider.models || []
    if (!modelSearch) return models
    const q = modelSearch.toLowerCase()
    return models.filter(m =>
      m.name.toLowerCase().includes(q) || m.id.toLowerCase().includes(q) || m.family.toLowerCase().includes(q)
    )
  }, [selectedProvider, modelSearch])

  const handleSave = async () => {
    if (!selectedProvider || !selectedModel || !apiKey) {
      setError('Provider, model ve API key gerekli')
      return
    }
    setSaving(true); setError(null)
    try {
      const res = await aiApi.setConfig({
        provider_id: selectedProvider.id,
        provider_name: selectedProvider.name,
        model_id: selectedModel.id,
        model_name: selectedModel.name,
        api_key: apiKey,
        base_url: selectedProvider.api,
      })
      if (res.error) throw new Error(res.error)
      setSuccess('AI provider configured: ' + selectedProvider.name + ' / ' + selectedModel.name)
      setApiKey('')
      refresh()
    } catch (e: any) { setError(e.message) } finally { setSaving(false) }
  }

  const handleTest = async () => {
    setTesting(true); setTestResult(null)
    try { setTestResult(await aiApi.test()) } catch { setTestResult({ status: 'error', message: 'Connection failed' }) }
    finally { setTesting(false) }
  }

  const handleAnalyze = async () => {
    setAnalyzing(true); setAnalyzeResult(null); setError(null)
    try {
      const res = await aiApi.analyze(20)
      if (res.error && !res.summary) setError(res.error)
      else { setAnalyzeResult(res); refresh() }
    } catch (e: any) { setError(e.message) } finally { setAnalyzing(false) }
  }

  if (loading) return <div className="flex items-center justify-center py-20"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>

  return (
    <div className="space-y-4 pb-20">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Brain className="h-5 w-5 text-accent" />
          <h1 className="text-lg font-semibold text-foreground">AI Threat Analysis</h1>
          <span className="text-xs text-muted-foreground ml-1">({providers.length} providers synced from models.dev)</span>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={() => { fetchProviders(); refresh() }}>
            <RefreshCw size={14} className="mr-1" /> Sync
          </Button>
          {config?.api_key_set && (
            <Button onClick={handleAnalyze} disabled={analyzing} size="sm">
              {analyzing ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Zap className="h-4 w-4 mr-1" />}
              Analyze Now
            </Button>
          )}
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive flex items-center gap-2">
          <XCircle size={16} /> {error}
          <button onClick={() => setError(null)} className="ml-auto text-xs underline">dismiss</button>
        </div>
      )}
      {success && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400 flex items-center gap-2">
          <CheckCircle2 size={16} /> {success}
          <button onClick={() => setSuccess(null)} className="ml-auto text-xs underline">dismiss</button>
        </div>
      )}

      {/* Stats */}
      {stats?.enabled && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <StatCard icon={Zap} label="Requests / Hour" value={stats.requests_hour} max="/ 30" />
          <StatCard icon={Activity} label="Tokens / Hour" value={stats.tokens_used_hour.toLocaleString()} max="/ 50K" />
          <StatCard icon={DollarSign} label="Total Cost" value={`$${(stats.total_cost_usd ?? 0).toFixed(4)}`} />
          <StatCard icon={Ban} label="AI Blocks" value={stats.blocks_triggered} sub={`${stats.monitors_triggered} monitors`} />
          <StatCard icon={Brain} label="Total Analyses" value={stats.total_requests} sub={`${stats.total_tokens_used.toLocaleString()} tokens`} />
        </div>
      )}

      {/* Current Config */}
      {config?.api_key_set && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/30 px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-emerald-900/50 flex items-center justify-center">
              <Cpu size={16} className="text-emerald-400" />
            </div>
            <div>
              <div className="text-sm font-medium text-foreground">{config.provider_name || config.provider_id} — {config.model_name || config.model_id}</div>
              <div className="text-[10px] text-muted-foreground flex items-center gap-1"><Lock size={8} /> {config.api_key_mask} &middot; {config.base_url}</div>
            </div>
          </div>
          <Button size="sm" variant="outline" onClick={handleTest} disabled={testing}>
            {testing ? <Loader2 className="h-3 w-3 animate-spin" /> : <CheckCircle2 size={14} className="mr-1" />}
            Test
          </Button>
        </div>
      )}
      {testResult && (
        <div className={cn('rounded-lg border px-4 py-2 text-sm flex items-center gap-2',
          testResult.status === 'ok' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400' : 'border-red-500/30 bg-red-500/10 text-red-400'
        )}>
          {testResult.status === 'ok' ? <CheckCircle2 size={14} /> : <XCircle size={14} />} {testResult.message}
        </div>
      )}

      {/* Analysis Result */}
      {analyzeResult && (
        <Section title="Analysis Result" defaultOpen>
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">{analyzeResult.summary}</p>
            {analyzeResult.threats_detected?.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {analyzeResult.threats_detected.map((t, i) => (
                  <span key={i} className="text-[10px] px-2 py-0.5 rounded-full bg-red-900/40 text-red-300 border border-red-700/30">{t}</span>
                ))}
              </div>
            )}
            {analyzeResult.verdicts?.map((v, i) => <VerdictRow key={i} verdict={v} />)}
            <div className="flex gap-4 text-[10px] text-muted-foreground">
              <span>{analyzeResult.tokens_used} tokens</span>
              <span>${(analyzeResult.cost_usd ?? 0).toFixed(4)}</span>
              <span>{analyzeResult.duration_ms}ms</span>
              <span>{analyzeResult.event_count} events analyzed</span>
            </div>
          </div>
        </Section>
      )}

      {/* Provider Selection */}
      <Section title={`Select AI Provider (${providers.length} available)`} defaultOpen={!config?.api_key_set}>
        <div className="space-y-3">
          {/* Search */}
          <div className="relative">
            <Search size={14} className="absolute left-3 top-2.5 text-muted-foreground" />
            <Input placeholder="Search providers..." value={providerSearch} onChange={e => setProviderSearch(e.target.value)} className="pl-8" />
          </div>

          {loadingProviders && <div className="text-center py-4"><Loader2 className="h-5 w-5 animate-spin mx-auto text-muted-foreground" /></div>}

          {/* Provider Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 max-h-[300px] overflow-y-auto pr-1">
            {filteredProviders.slice(0, 30).map(p => (
              <button
                key={p.id}
                onClick={() => { setSelectedProvider(p); setSelectedModel(null); setModelSearch('') }}
                className={cn(
                  'text-left rounded-lg border px-3 py-2.5 transition-all hover:border-accent/50',
                  selectedProvider?.id === p.id
                    ? 'border-accent bg-accent/10 ring-1 ring-accent/30'
                    : 'border-border bg-card/30 hover:bg-card/50'
                )}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-foreground truncate">{p.name}</span>
                  <span className="text-[9px] text-muted-foreground shrink-0 ml-1">{p.model_count} models</span>
                </div>
                {p.doc && (
                  <div className="text-[9px] text-muted-foreground truncate mt-0.5 flex items-center gap-0.5">
                    <ExternalLink size={8} /> {p.api}
                  </div>
                )}
              </button>
            ))}
          </div>
          {filteredProviders.length > 30 && (
            <p className="text-[10px] text-muted-foreground text-center">Showing 30 of {filteredProviders.length} — refine your search</p>
          )}

          {/* Model Selection */}
          {selectedProvider && (
            <div className="border-t border-border pt-3 mt-3">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs font-medium text-foreground">{selectedProvider.name} — Models ({selectedProvider.models?.length || 0})</h4>
                <Input placeholder="Search models..." value={modelSearch} onChange={e => setModelSearch(e.target.value)}
                  className="w-48 h-7 text-xs" />
              </div>
              <div className="space-y-1 max-h-[250px] overflow-y-auto pr-1">
                {filteredModels.map(m => (
                  <button
                    key={m.id}
                    onClick={() => setSelectedModel(m)}
                    className={cn(
                      'w-full text-left rounded-lg border px-3 py-2 transition-all',
                      selectedModel?.id === m.id
                        ? 'border-accent bg-accent/10 ring-1 ring-accent/30'
                        : 'border-border/50 bg-card/20 hover:bg-card/40 hover:border-border'
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-medium text-foreground">{m.name}</span>
                      <div className="flex gap-1.5">
                        {m.reasoning && <span className="text-[8px] px-1 rounded bg-purple-900/40 text-purple-300">reasoning</span>}
                        {m.tool_call && <span className="text-[8px] px-1 rounded bg-blue-900/40 text-blue-300">tools</span>}
                      </div>
                    </div>
                    <div className="flex gap-3 mt-0.5 text-[10px] text-muted-foreground">
                      <span>family: {m.family || '—'}</span>
                      <span>ctx: {m.context_window > 0 ? `${(m.context_window/1000).toFixed(0)}K` : '—'}</span>
                      <span>in: ${m.cost_input_per_m > 0 ? m.cost_input_per_m.toFixed(2) : '—'}/M</span>
                      <span>out: ${m.cost_output_per_m > 0 ? m.cost_output_per_m.toFixed(2) : '—'}/M</span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* API Key + Save */}
          {selectedModel && (
            <div className="border-t border-border pt-3 mt-3 space-y-3">
              <div className="rounded-lg border border-border bg-card/30 px-4 py-2.5 grid grid-cols-5 gap-2 text-xs">
                <div><span className="text-muted-foreground">Provider:</span> <span className="text-foreground font-medium">{selectedProvider?.name}</span></div>
                <div><span className="text-muted-foreground">Model:</span> <span className="text-foreground font-medium">{selectedModel.name}</span></div>
                <div><span className="text-muted-foreground">Context:</span> <span className="text-foreground">{selectedModel.context_window > 0 ? `${(selectedModel.context_window/1000).toFixed(0)}K` : '—'}</span></div>
                <div><span className="text-muted-foreground">Cost In:</span> <span className="text-foreground">${selectedModel.cost_input_per_m > 0 ? selectedModel.cost_input_per_m.toFixed(2) : '—'}/M</span></div>
                <div><span className="text-muted-foreground">Cost Out:</span> <span className="text-foreground">${selectedModel.cost_output_per_m > 0 ? selectedModel.cost_output_per_m.toFixed(2) : '—'}/M</span></div>
              </div>
              <div>
                <label className="text-xs text-muted-foreground mb-1 block">API Key</label>
                <Input type="password" placeholder="sk-... or your provider's API key" value={apiKey} onChange={e => setApiKey(e.target.value)} />
              </div>
              <Button onClick={handleSave} disabled={saving || !apiKey} className="w-full">
                {saving ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Sparkles className="h-4 w-4 mr-1" />}
                Save Provider Configuration
              </Button>
            </div>
          )}
        </div>
      </Section>

      {/* History */}
      <Section title={`Analysis History (${history.length})`} defaultOpen={history.length > 0}>
        {history.length === 0 ? (
          <div className="text-sm text-muted-foreground py-4 text-center">
            No analysis results yet. Configure a provider and click "Analyze Now".
          </div>
        ) : (
          <div className="space-y-2">
            {history.map(r => <HistoryItem key={r.id} result={r} />)}
          </div>
        )}
      </Section>
    </div>
  )
}

// --- Sub-components ---

function StatCard({ icon: Icon, label, value, max, sub }: { icon: any; label: string; value: any; max?: string; sub?: string }) {
  return (
    <div className="rounded-lg border border-border bg-card/50 px-3 py-2.5">
      <div className="flex items-center gap-1.5 mb-1">
        <Icon size={13} className="text-muted-foreground" />
        <span className="text-[10px] text-muted-foreground">{label}</span>
      </div>
      <div className="text-lg font-semibold text-foreground leading-none">
        {value}{max && <span className="text-xs text-muted-foreground font-normal ml-1">{max}</span>}
      </div>
      {sub && <div className="text-[10px] text-muted-foreground mt-0.5">{sub}</div>}
    </div>
  )
}

function VerdictRow({ verdict }: { verdict: Verdict }) {
  const cls = verdict.action === 'block' ? 'text-red-400 bg-red-900/40 border-red-700/30'
    : verdict.action === 'monitor' ? 'text-yellow-400 bg-yellow-900/40 border-yellow-700/30'
    : 'text-emerald-400 bg-emerald-900/40 border-emerald-700/30'
  const Icon = verdict.action === 'block' ? Ban : verdict.action === 'monitor' ? Eye : Shield
  return (
    <div className="flex items-center gap-2 rounded-lg border border-border bg-card/30 px-3 py-2">
      <span className={cn('text-[10px] px-1.5 py-0.5 rounded border flex items-center gap-1', cls)}>
        <Icon size={10} /> {verdict.action}
      </span>
      <span className="text-xs font-mono text-foreground">{verdict.ip}</span>
      <span className="text-xs text-muted-foreground flex-1 truncate">{verdict.reason}</span>
      <span className="text-[10px] text-muted-foreground">{((verdict.confidence ?? 0) * 100).toFixed(0)}%</span>
    </div>
  )
}

function HistoryItem({ result }: { result: AnalysisResult }) {
  const [open, setOpen] = useState(false)
  const hasError = Boolean(result.error)
  const ts = new Date(result.timestamp).toLocaleString()
  const blockCount = result.verdicts?.filter(v => v.action === 'block').length || 0
  const monitorCount = result.verdicts?.filter(v => v.action === 'monitor').length || 0
  return (
    <div className="rounded-lg border border-border bg-card/30 overflow-hidden">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center gap-3 px-3 py-2 hover:bg-card/50 transition-colors text-left">
        <Clock size={12} className="text-muted-foreground shrink-0" />
        <span className="text-xs text-muted-foreground shrink-0">{ts}</span>
        <span className="text-xs text-foreground">{result.event_count} events</span>
        {blockCount > 0 && <span className="text-[9px] px-1.5 rounded bg-red-900/40 text-red-300">{blockCount} blocks</span>}
        {monitorCount > 0 && <span className="text-[9px] px-1.5 rounded bg-yellow-900/40 text-yellow-300">{monitorCount} monitors</span>}
        {hasError && <span className="text-[9px] px-1.5 rounded bg-red-900/40 text-red-400">error</span>}
        <span className="text-[10px] text-muted-foreground ml-auto shrink-0">{result.tokens_used ?? 0} tok / ${(result.cost_usd ?? 0).toFixed(4)} / {result.duration_ms ?? 0}ms</span>
        <ChevronDown size={14} className={cn('text-muted-foreground transition-transform shrink-0', open && 'rotate-180')} />
      </button>
      {open && (
        <div className="border-t border-border px-3 py-2 space-y-2">
          {result.summary && <p className="text-xs text-muted-foreground">{result.summary}</p>}
          {result.error && <p className="text-xs text-red-400">{result.error}</p>}
          {result.threats_detected?.length > 0 && (
            <div className="flex flex-wrap gap-1">{result.threats_detected.map((t, i) => (
              <span key={i} className="text-[9px] px-1.5 py-0.5 rounded-full bg-red-900/30 text-red-300">{t}</span>
            ))}</div>
          )}
          {result.verdicts?.map((v, i) => <VerdictRow key={i} verdict={v} />)}
          <div className="text-[10px] text-muted-foreground">Model: {result.model}</div>
        </div>
      )}
    </div>
  )
}
