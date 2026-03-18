import { useState, useEffect } from 'react'
import { api } from '@/lib/api'
import type { CustomRule, GeoIPResult } from '@/lib/api'
import { cn } from '@/lib/utils'
import { Plus, Trash2, Save, X, Search, ShieldCheck } from 'lucide-react'

const FIELDS = [
  { value: 'path', label: 'Path' }, { value: 'method', label: 'Method' },
  { value: 'ip', label: 'Client IP' }, { value: 'country', label: 'Country (GeoIP)' },
  { value: 'user_agent', label: 'User Agent' }, { value: 'host', label: 'Host' },
  { value: 'query', label: 'Query String' }, { value: 'body_size', label: 'Body Size' },
  { value: 'content_type', label: 'Content Type' }, { value: 'score', label: 'Current Score' },
]
const OPS = [
  { value: 'equals', label: '=' }, { value: 'not_equals', label: '!=' },
  { value: 'contains', label: 'contains' }, { value: 'not_contains', label: '!contains' },
  { value: 'starts_with', label: 'starts with' }, { value: 'ends_with', label: 'ends with' },
  { value: 'matches', label: 'regex' }, { value: 'in', label: 'in list' },
  { value: 'in_cidr', label: 'in CIDR' }, { value: 'greater_than', label: '>' },
  { value: 'less_than', label: '<' },
]
const ACTIONS = [
  { value: 'block', label: 'Block', color: 'bg-destructive/15 text-destructive' },
  { value: 'challenge', label: 'Challenge', color: 'bg-orange/15 text-orange' },
  { value: 'log', label: 'Log', color: 'bg-warning/15 text-warning' },
  { value: 'pass', label: 'Pass', color: 'bg-success/15 text-success' },
]

function newRule(): CustomRule {
  return { id: 'rule-' + Date.now(), name: '', enabled: true, priority: 10,
    conditions: [{ field: 'path', op: 'starts_with', value: '/' }], action: 'block', score: 50 }
}

export default function RulesPage() {
  const [rules, setRules] = useState<CustomRule[]>([])
  const [editing, setEditing] = useState<CustomRule | null>(null)
  const [isNew, setIsNew] = useState(false)
  const [toast, setToast] = useState<{msg: string; err: boolean} | null>(null)
  const [sortKey, setSortKey] = useState<'priority' | 'name' | 'action' | 'score'>('priority')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [geoIP, setGeoIP] = useState('')
  const [geoResult, setGeoResult] = useState<GeoIPResult | null>(null)

  const load = () => api.getRules().then(d => setRules(d.rules || [])).catch(() => {})
  useEffect(() => { load() }, [])

  const flash = (msg: string, err = false) => { setToast({msg, err}); setTimeout(() => setToast(null), 3000) }

  const save = async () => {
    if (!editing) return
    try {
      if (isNew) await api.addRule(editing)
      else await api.updateRule(editing.id, editing)
      flash(isNew ? 'Rule created' : 'Rule updated')
      setEditing(null); load()
    } catch (e) { flash((e as Error).message, true) }
  }

  const del = async (id: string) => {
    try { await api.deleteRule(id); flash('Deleted'); load() }
    catch (e) { flash((e as Error).message, true) }
  }

  const toggle = async (id: string, on: boolean) => {
    const r = rules.find(x => x.id === id)
    if (!r) return
    try { await api.updateRule(id, {...r, enabled: on}); load() }
    catch (e) { flash((e as Error).message, true) }
  }

  const geo = async () => {
    if (!geoIP.trim()) return
    try { setGeoResult(await api.geoipLookup(geoIP.trim())) }
    catch (e) { flash((e as Error).message, true) }
  }

  const toggleSort = (key: typeof sortKey) => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setSortDir('asc') }
  }

  const sorted = [...rules].sort((a, b) => {
    let cmp = 0
    switch (sortKey) {
      case 'priority': cmp = a.priority - b.priority; break
      case 'name': cmp = (a.name || a.id).localeCompare(b.name || b.id); break
      case 'action': cmp = a.action.localeCompare(b.action); break
      case 'score': cmp = a.score - b.score; break
    }
    return sortDir === 'desc' ? -cmp : cmp
  })

  const SortTh = ({k, children, className}: {k: typeof sortKey; children: React.ReactNode; className?: string}) => (
    <th className={cn('text-left px-3 py-2 cursor-pointer select-none hover:text-foreground transition-colors', className)}
      onClick={() => toggleSort(k)}>
      {children} {sortKey === k && <span className="text-accent">{sortDir === 'asc' ? '\u25B2' : '\u25BC'}</span>}
    </th>
  )

  const Tog = ({on, onClick}: {on: boolean; onClick: () => void}) => (
    <button type="button" onClick={onClick} className={cn('h-5 w-9 rounded-full transition-colors relative', on ? 'bg-accent' : 'bg-border')}>
      <span className={cn('absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white transition-transform', on && 'translate-x-4')} />
    </button>
  )

  return (
    <div className="space-y-4">
      {toast && <div className={cn('fixed top-4 right-4 z-50 rounded-lg px-4 py-3 text-sm text-white shadow-lg', toast.err ? 'bg-destructive' : 'bg-success')}>{toast.msg}</div>}

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-accent" />
          <h1 className="text-lg font-semibold">Custom Rules</h1>
          <span className="text-xs text-muted">({rules.length})</span>
        </div>
        <button onClick={() => { setEditing(newRule()); setIsNew(true) }} className="flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-white hover:opacity-90">
          <Plus className="h-4 w-4" /> Add Rule
        </button>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <table className="w-full text-sm">
          <thead><tr className="border-b border-border text-muted text-xs">
            <th className="text-left px-3 py-2 w-12">On</th>
            <SortTh k="priority" className="w-10">Pri</SortTh>
            <SortTh k="name">Name</SortTh>
            <th className="text-left px-3 py-2 hidden md:table-cell">Conditions</th>
            <SortTh k="action" className="w-24">Action</SortTh>
            <SortTh k="score" className="w-14">Score</SortTh>
            <th className="w-10"></th>
          </tr></thead>
          <tbody>
            {sorted.length === 0 && <tr><td colSpan={7} className="text-center py-8 text-muted">No rules yet. Click Add Rule.</td></tr>}
            {sorted.map(r => (
              <tr key={r.id} className="border-b border-border hover:bg-card/80 cursor-pointer transition-colors"
                onClick={() => { setEditing({...r, conditions: [...(r.conditions||[])]}); setIsNew(false) }}>
                <td className="px-3 py-2" onClick={e => e.stopPropagation()}><Tog on={r.enabled} onClick={() => toggle(r.id, !r.enabled)} /></td>
                <td className="px-3 py-2 font-mono text-xs text-muted">{r.priority}</td>
                <td className="px-3 py-2 font-medium">{r.name || r.id}</td>
                <td className="px-3 py-2 text-xs text-muted max-w-[250px] truncate hidden md:table-cell">
                  {(r.conditions||[]).map(c => `${c.field} ${c.op} ${typeof c.value === 'string' ? c.value : JSON.stringify(c.value)}`).join(' AND ')}
                </td>
                <td className="px-3 py-2"><span className={cn('px-2 py-0.5 rounded text-[10px] font-bold uppercase', ACTIONS.find(a => a.value === r.action)?.color || '')}>{r.action}</span></td>
                <td className="px-3 py-2 font-mono text-xs">{r.score}</td>
                <td className="px-3 py-2" onClick={e => e.stopPropagation()}><button onClick={() => del(r.id)} className="text-muted hover:text-destructive"><Trash2 className="h-3.5 w-3.5" /></button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Editor Modal */}
      {editing && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setEditing(null)}>
          <div className="bg-card border border-border rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-6 py-4 border-b border-border">
              <h2 className="font-semibold">{isNew ? 'Create Rule' : 'Edit Rule'}</h2>
              <button onClick={() => setEditing(null)} className="p-1 hover:bg-background rounded"><X className="h-4 w-4" /></button>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <Field label="Rule ID"><input value={editing.id} onChange={e => setEditing({...editing, id: e.target.value})} disabled={!isNew} className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-accent font-mono disabled:opacity-50" /></Field>
                <Field label="Name"><input value={editing.name} onChange={e => setEditing({...editing, name: e.target.value})} placeholder="Block admin from CN" className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-accent" /></Field>
              </div>
              <div className="grid grid-cols-4 gap-4">
                <Field label="Priority"><input type="number" value={editing.priority} min={0} onChange={e => setEditing({...editing, priority: Number(e.target.value)})} className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-accent font-mono" /></Field>
                <Field label="Action">
                  <select value={editing.action} onChange={e => setEditing({...editing, action: e.target.value})} className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-accent">
                    {ACTIONS.map(a => <option key={a.value} value={a.value}>{a.label}</option>)}
                  </select>
                </Field>
                <Field label="Score"><input type="number" value={editing.score} min={0} onChange={e => setEditing({...editing, score: Number(e.target.value)})} className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-accent font-mono" /></Field>
                <div className="flex items-end pb-1"><label className="flex items-center gap-2 text-sm"><Tog on={editing.enabled} onClick={() => setEditing({...editing, enabled: !editing.enabled})} /> Enabled</label></div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-muted uppercase">Conditions (AND)</span>
                  <button onClick={() => setEditing({...editing, conditions: [...editing.conditions, {field:'path',op:'contains',value:''}]})} className="text-xs text-accent hover:underline flex items-center gap-1"><Plus className="h-3 w-3" /> Add</button>
                </div>
                <div className="space-y-2">
                  {editing.conditions.map((c, i) => (
                    <div key={i} className="flex items-center gap-2 rounded-md bg-background border border-border p-2">
                      <select value={c.field} onChange={e => { const cs=[...editing.conditions]; cs[i]={...cs[i],field:e.target.value}; setEditing({...editing,conditions:cs}) }} className="rounded border border-border bg-card px-2 py-1 text-xs text-foreground min-w-[120px]">
                        {FIELDS.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
                        <option value="header:">Header...</option>
                        <option value="cookie:">Cookie...</option>
                      </select>
                      <select value={c.op} onChange={e => { const cs=[...editing.conditions]; cs[i]={...cs[i],op:e.target.value}; setEditing({...editing,conditions:cs}) }} className="rounded border border-border bg-card px-2 py-1 text-xs text-foreground min-w-[90px]">
                        {OPS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                      </select>
                      <input
                        value={typeof c.value === 'string' ? c.value : JSON.stringify(c.value)}
                        onChange={e => {
                          const cs=[...editing.conditions]
                          let v: unknown = e.target.value
                          if (c.op === 'in' || c.op === 'not_in') { try { v = JSON.parse(e.target.value) } catch { /* keep as string */ } }
                          cs[i] = {...cs[i], value: v}
                          setEditing({...editing, conditions: cs})
                        }}
                        placeholder={c.op === 'in' ? '["US","CN"]' : 'value'}
                        className="flex-1 rounded border border-border bg-card px-2 py-1 text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-accent"
                      />
                      <button onClick={() => { const cs=[...editing.conditions]; cs.splice(i,1); setEditing({...editing,conditions:cs}) }} className="text-muted hover:text-destructive p-1"><X className="h-3 w-3" /></button>
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button onClick={() => setEditing(null)} className="rounded-md border border-border px-4 py-2 text-sm hover:bg-background">Cancel</button>
                <button onClick={save} className="flex items-center gap-1.5 rounded-md bg-accent px-4 py-2 text-sm font-medium text-white hover:opacity-90"><Save className="h-4 w-4" /> {isNew ? 'Create' : 'Save'}</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* GeoIP */}
      <div className="rounded-lg border border-border bg-card p-4">
        <h3 className="text-sm font-semibold mb-3 flex items-center gap-2"><Search className="h-4 w-4 text-muted" /> GeoIP Lookup</h3>
        <div className="flex items-center gap-2">
          <input value={geoIP} onChange={e => setGeoIP(e.target.value)} onKeyDown={e => e.key === 'Enter' && geo()} placeholder="1.2.3.4"
            className="rounded-md border border-border bg-background px-3 py-1.5 text-sm font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-accent w-48" />
          <button onClick={geo} className="rounded-md bg-accent px-3 py-1.5 text-sm text-white hover:opacity-90">Lookup</button>
          {geoResult && <span className="text-sm"><span className="font-bold">{geoResult.country || '??'}</span> <span className="text-muted">{geoResult.name}</span></span>}
        </div>
      </div>
    </div>
  )
}

function Field({label, children}: {label: string; children: React.ReactNode}) {
  return <div><label className="text-xs text-muted block mb-1">{label}</label>{children}</div>
}
