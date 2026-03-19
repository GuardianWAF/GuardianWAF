import { useState, useEffect, useCallback } from 'react'
import { api } from '@/lib/api'
import type { WafConfig, IpAclData, BanEntry } from '@/lib/api'
import { cn } from '@/lib/utils'
import { Section } from '@/components/config/section'
import { Switch } from '@/components/ui/switch'
import { Input } from '@/components/ui/input'
import { Select, SelectOption } from '@/components/ui/select'
import { Button } from '@/components/ui/button'
import { Save, Plus, X, Loader2 } from 'lucide-react'

const DETECTORS = ['sqli', 'xss', 'lfi', 'cmdi', 'xxe', 'ssrf'] as const
type DetectorKey = (typeof DETECTORS)[number]

const DETECTOR_LABELS: Record<DetectorKey, string> = {
  sqli: 'SQL Injection',
  xss: 'Cross-Site Scripting',
  lfi: 'Local File Inclusion',
  cmdi: 'Command Injection',
  xxe: 'XML External Entity',
  ssrf: 'Server-Side Request Forgery',
}

// Deep clone helper
function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v))
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function get(obj: Record<string, any>, path: string): any {
  return path.split('.').reduce((o, k) => {
    if (o === undefined || o === null) return undefined
    // Try exact key first, then capitalized (Go JSON serialization)
    if (o[k] !== undefined) return o[k]
    const cap = k.charAt(0).toUpperCase() + k.slice(1)
    return o[cap]
  }, obj)
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function set(obj: Record<string, any>, path: string, value: any) {
  const keys = path.split('.')
  const last = keys.pop()!
  const target = keys.reduce((o, k) => {
    if (o[k] === undefined) o[k] = {}
    return o[k]
  }, obj)
  target[last] = value
}

export default function ConfigPage() {
  const [config, setConfig] = useState<WafConfig | null>(null)
  const [original, setOriginal] = useState<string>('')
  const [ipacl, setIpacl] = useState<IpAclData>({ whitelist: [], blacklist: [] })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  // IP input states
  const [whitelistInput, setWhitelistInput] = useState('')
  const [blacklistInput, setBlacklistInput] = useState('')

  // Temp bans
  const [bans, setBans] = useState<BanEntry[]>([])
  const [banIP, setBanIP] = useState('')
  const [banDuration, setBanDuration] = useState('1h')
  const [banReason, setBanReason] = useState('')

  const fetchData = useCallback(() => {
    api.getConfig().then((data) => {
      setConfig(data)
      setOriginal(JSON.stringify(data))
    }).catch(() => setError('Failed to load configuration'))

    api.getIPACL().then(setIpacl).catch(() => {})
    api.getBans().then(d => setBans(d.bans || [])).catch(() => {})
  }, [])

  useEffect(() => { fetchData() }, [fetchData])

  const dirty = config !== null && JSON.stringify(config) !== original

  const update = (path: string, value: unknown) => {
    setConfig((prev) => {
      if (!prev) return prev
      const next = clone(prev)
      if (path === 'mode') {
        next.mode = value as string
      } else if (path.startsWith('tls.')) {
        if (!next.tls) next.tls = {}
        set(next.tls, path.slice(4), value)
      } else {
        set(next.waf, path, value)
      }
      return next
    })
  }

  const val = (path: string, fallback: unknown = '') => {
    if (!config) return fallback
    if (path === 'mode') return config.mode
    if (path.startsWith('tls.')) return get(config.tls || {}, path.slice(4)) ?? fallback
    return get(config.waf, path) ?? fallback
  }

  const handleSave = async () => {
    if (!config) return
    setSaving(true)
    setError(null)
    setSuccess(null)
    try {
      await api.updateConfig(config)
      setOriginal(JSON.stringify(config))
      setSuccess('Configuration saved successfully')
      setTimeout(() => setSuccess(null), 3000)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  const addIP = async (list: 'whitelist' | 'blacklist', ip: string) => {
    if (!ip.trim()) return
    try {
      await api.addIP(list, ip.trim())
      setIpacl((prev) => ({
        ...prev,
        [list]: [...prev[list], ip.trim()],
      }))
      if (list === 'whitelist') setWhitelistInput('')
      else setBlacklistInput('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add IP')
    }
  }

  const removeIP = async (list: 'whitelist' | 'blacklist', ip: string) => {
    try {
      await api.removeIP(list, ip)
      setIpacl((prev) => ({
        ...prev,
        [list]: prev[list].filter((v) => v !== ip),
      }))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove IP')
    }
  }

  if (!config) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-4 pb-20">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-foreground">WAF Configuration</h1>
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

      {/* General */}
      <Section title="General" defaultOpen>
        <div className="space-y-4">
          <FieldRow label="WAF Mode">
            <Select
              value={val('mode', 'enforce') as string}
              onChange={(e) => update('mode', e.target.value)}
              className="w-48"
            >
              <SelectOption value="enforce">Enforce</SelectOption>
              <SelectOption value="monitor">Monitor</SelectOption>
              <SelectOption value="disabled">Disabled</SelectOption>
            </Select>
          </FieldRow>
        </div>
      </Section>

      {/* TLS / SSL */}
      <Section
        title="TLS / SSL"
        badge={{ on: val('tls.enabled', false) as boolean }}
      >
        <div className="space-y-4">
          <FieldRow label="TLS Enabled">
            <Switch
              checked={val('tls.enabled', false) as boolean}
              onCheckedChange={(v) => update('tls.enabled', v)}
            />
          </FieldRow>
          <FieldRow label="HTTPS Listen Address">
            <Input
              value={val('tls.listen', ':8443') as string}
              onChange={(e) => update('tls.listen', e.target.value)}
              className="w-32 font-mono"
              placeholder=":8443"
            />
          </FieldRow>
          <FieldRow label="Certificate File">
            <Input
              value={val('tls.cert_file', '') as string}
              onChange={(e) => update('tls.cert_file', e.target.value)}
              className="w-64 font-mono"
              placeholder="/etc/certs/cert.pem"
            />
          </FieldRow>
          <FieldRow label="Key File">
            <Input
              value={val('tls.key_file', '') as string}
              onChange={(e) => update('tls.key_file', e.target.value)}
              className="w-64 font-mono"
              placeholder="/etc/certs/key.pem"
            />
          </FieldRow>
          <FieldRow label="HTTP → HTTPS Redirect">
            <Switch
              checked={val('tls.http_redirect', true) as boolean}
              onCheckedChange={(v) => update('tls.http_redirect', v)}
            />
          </FieldRow>

          <div className="border-t border-border pt-4 mt-4">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
              ACME / Let&apos;s Encrypt
            </h4>
            <div className="space-y-4">
              <FieldRow label="ACME Enabled">
                <Switch
                  checked={val('tls.acme.enabled', false) as boolean}
                  onCheckedChange={(v) => update('tls.acme.enabled', v)}
                />
              </FieldRow>
              <FieldRow label="Email">
                <Input
                  value={val('tls.acme.email', '') as string}
                  onChange={(e) => update('tls.acme.email', e.target.value)}
                  className="w-64"
                  placeholder="admin@example.com"
                />
              </FieldRow>
              <FieldRow label="Cache Directory">
                <Input
                  value={val('tls.acme.cache_dir', '') as string}
                  onChange={(e) => update('tls.acme.cache_dir', e.target.value)}
                  className="w-64 font-mono"
                  placeholder="/var/lib/guardianwaf/acme"
                />
              </FieldRow>
            </div>
          </div>
        </div>
      </Section>

      {/* Detection Engine */}
      <Section
        title="Detection Engine"
        badge={{ on: val('detection.enabled', true) as boolean }}
        defaultOpen
      >
        <div className="space-y-6">
          <FieldRow label="Enabled">
            <Switch
              checked={val('detection.enabled', true) as boolean}
              onCheckedChange={(v) => update('detection.enabled', v)}
            />
          </FieldRow>
          <FieldRow label="Block Threshold">
            <Input
              type="number"
              value={val('detection.threshold.block', 50) as number}
              onChange={(e) => update('detection.threshold.block', Number(e.target.value))}
              className="w-24"
              min={0}
              max={100}
            />
          </FieldRow>
          <FieldRow label="Log Threshold">
            <Input
              type="number"
              value={val('detection.threshold.log', 25) as number}
              onChange={(e) => update('detection.threshold.log', Number(e.target.value))}
              className="w-24"
              min={0}
              max={100}
            />
          </FieldRow>

          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
              Detectors
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {DETECTORS.map((key) => (
                <div
                  key={key}
                  className="rounded-md border border-border bg-background p-3 space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-foreground">
                      {DETECTOR_LABELS[key]}
                    </span>
                    <Switch
                      checked={val(`detection.detectors.${key}.enabled`, true) as boolean}
                      onCheckedChange={(v) =>
                        update(`detection.detectors.${key}.enabled`, v)
                      }
                    />
                  </div>
                  <FieldRow label="Multiplier">
                    <Input
                      type="number"
                      value={val(`detection.detectors.${key}.multiplier`, 1.0) as number}
                      onChange={(e) =>
                        update(
                          `detection.detectors.${key}.multiplier`,
                          parseFloat(e.target.value) || 0,
                        )
                      }
                      className="w-20"
                      min={0}
                      max={10}
                      step={0.1}
                    />
                  </FieldRow>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Section>

      {/* Bot Detection */}
      <Section
        title="Bot Detection"
        badge={{ on: val('bot_detection.enabled', false) as boolean }}
      >
        <div className="space-y-4">
          <FieldRow label="Enabled">
            <Switch
              checked={val('bot_detection.enabled', false) as boolean}
              onCheckedChange={(v) => update('bot_detection.enabled', v)}
            />
          </FieldRow>
          <FieldRow label="Mode">
            <Select
              value={val('bot_detection.mode', 'enforce') as string}
              onChange={(e) => update('bot_detection.mode', e.target.value)}
              className="w-40"
            >
              <SelectOption value="enforce">Enforce</SelectOption>
              <SelectOption value="monitor">Monitor</SelectOption>
            </Select>
          </FieldRow>
          <FieldRow label="Block Empty User-Agent">
            <Switch
              checked={val('bot_detection.user_agent.block_empty', false) as boolean}
              onCheckedChange={(v) => update('bot_detection.user_agent.block_empty', v)}
            />
          </FieldRow>
          <FieldRow label="Block Scanners">
            <Switch
              checked={val('bot_detection.user_agent.block_known_scanners', false) as boolean}
              onCheckedChange={(v) => update('bot_detection.user_agent.block_known_scanners', v)}
            />
          </FieldRow>
          <FieldRow label="RPS Threshold">
            <Input
              type="number"
              value={val('bot_detection.behavior.rps_threshold', 100) as number}
              onChange={(e) =>
                update('bot_detection.behavior.rps_threshold', Number(e.target.value))
              }
              className="w-24"
              min={1}
            />
          </FieldRow>
          <FieldRow label="Error Rate Threshold">
            <Input
              type="number"
              value={val('bot_detection.behavior.error_rate_threshold', 0.5) as number}
              onChange={(e) =>
                update(
                  'bot_detection.behavior.error_rate_threshold',
                  parseFloat(e.target.value) || 0,
                )
              }
              className="w-24"
              min={0}
              max={1}
              step={0.01}
            />
          </FieldRow>
        </div>
      </Section>

      {/* JS Challenge */}
      <Section
        title="JS Challenge (PoW)"
        badge={{ on: val('challenge.enabled', false) as boolean }}
      >
        <div className="space-y-4">
          <FieldRow label="Enabled">
            <Switch
              checked={val('challenge.enabled', false) as boolean}
              onCheckedChange={(v) => update('challenge.enabled', v)}
            />
          </FieldRow>
          <FieldRow label="Difficulty">
            <Input
              type="number"
              value={val('challenge.difficulty', 16) as number}
              onChange={(e) =>
                update('challenge.difficulty', Number(e.target.value))
              }
              className="w-24"
              min={8}
              max={32}
            />
          </FieldRow>
        </div>
      </Section>

      {/* Rate Limiting */}
      <Section
        title="Rate Limiting"
        badge={{ on: val('rate_limit.enabled', false) as boolean }}
      >
        <div className="space-y-4">
          <FieldRow label="Enabled">
            <Switch
              checked={val('rate_limit.enabled', false) as boolean}
              onCheckedChange={(v) => update('rate_limit.enabled', v)}
            />
          </FieldRow>
        </div>
      </Section>

      {/* IP Access Control */}
      <Section
        title="IP Access Control"
        badge={{ on: val('ip_acl.enabled', false) as boolean }}
      >
        <div className="space-y-6">
          <div className="flex items-center gap-6">
            <FieldRow label="Enabled">
              <Switch
                checked={val('ip_acl.enabled', false) as boolean}
                onCheckedChange={(v) => update('ip_acl.enabled', v)}
              />
            </FieldRow>
            <FieldRow label="Auto-Ban">
              <Switch
                checked={val('ip_acl.auto_ban.enabled', false) as boolean}
                onCheckedChange={(v) => update('ip_acl.auto_ban.enabled', v)}
              />
            </FieldRow>
          </div>

          {/* Whitelist */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
              Whitelist
            </h4>
            <div className="flex items-center gap-2 mb-3">
              <Input
                placeholder="IP or CIDR (e.g. 10.0.0.0/8)"
                value={whitelistInput}
                onChange={(e) => setWhitelistInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') addIP('whitelist', whitelistInput)
                }}
                className="font-mono max-w-xs"
              />
              <Button
                size="sm"
                variant="secondary"
                onClick={() => addIP('whitelist', whitelistInput)}
              >
                <Plus className="h-3.5 w-3.5" />
                Add
              </Button>
            </div>
            <div className="flex flex-wrap gap-2">
              {(ipacl.whitelist || []).map((ip) => (
                <IPChip key={ip} ip={ip} onRemove={() => removeIP('whitelist', ip)} />
              ))}
              {(ipacl.whitelist || []).length === 0 && (
                <span className="text-xs text-muted-foreground">No entries</span>
              )}
            </div>
          </div>

          {/* Blacklist */}
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
              Blacklist
            </h4>
            <div className="flex items-center gap-2 mb-3">
              <Input
                placeholder="IP or CIDR (e.g. 192.168.1.100)"
                value={blacklistInput}
                onChange={(e) => setBlacklistInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') addIP('blacklist', blacklistInput)
                }}
                className="font-mono max-w-xs"
              />
              <Button
                size="sm"
                variant="secondary"
                onClick={() => addIP('blacklist', blacklistInput)}
              >
                <Plus className="h-3.5 w-3.5" />
                Add
              </Button>
            </div>
            <div className="flex flex-wrap gap-2">
              {(ipacl.blacklist || []).map((ip) => (
                <IPChip key={ip} ip={ip} variant="destructive" onRemove={() => removeIP('blacklist', ip)} />
              ))}
              {(ipacl.blacklist || []).length === 0 && (
                <span className="text-xs text-muted-foreground">No entries</span>
              )}
            </div>
          </div>

          {/* Temporary Bans */}
          <div className="border-t border-border pt-4 mt-4">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
              Temporary Bans
            </h4>
            <div className="flex items-center gap-2 mb-3">
              <Input
                placeholder="IP address"
                value={banIP}
                onChange={(e) => setBanIP(e.target.value)}
                className="font-mono w-40"
              />
              <Select
                value={banDuration}
                onChange={(e) => setBanDuration(e.target.value)}
                className="w-28"
              >
                <SelectOption value="5m">5 min</SelectOption>
                <SelectOption value="15m">15 min</SelectOption>
                <SelectOption value="30m">30 min</SelectOption>
                <SelectOption value="1h">1 hour</SelectOption>
                <SelectOption value="6h">6 hours</SelectOption>
                <SelectOption value="24h">24 hours</SelectOption>
                <SelectOption value="168h">7 days</SelectOption>
              </Select>
              <Input
                placeholder="Reason (optional)"
                value={banReason}
                onChange={(e) => setBanReason(e.target.value)}
                className="flex-1"
              />
              <Button
                size="sm"
                variant="destructive"
                onClick={async () => {
                  if (!banIP.trim()) return
                  try {
                    await api.addBan(banIP.trim(), banDuration, banReason || undefined)
                    setBanIP(''); setBanReason('')
                    setSuccess('IP banned: ' + banIP.trim())
                    setTimeout(() => setSuccess(null), 3000)
                    api.getBans().then(d => setBans(d.bans || []))
                  } catch (err) { setError(err instanceof Error ? err.message : 'Ban failed') }
                }}
              >
                Ban
              </Button>
            </div>
            {bans.length > 0 ? (
              <div className="space-y-1">
                {bans.map((ban) => (
                  <div key={ban.ip} className="flex items-center justify-between rounded-md bg-destructive/5 border border-destructive/20 px-3 py-2 text-sm">
                    <div className="flex items-center gap-3">
                      <span className="font-mono font-medium">{ban.ip}</span>
                      <span className="text-xs text-muted-foreground">{ban.reason}</span>
                      <span className="text-xs text-destructive">
                        expires {new Date(ban.expires_at).toLocaleString()}
                      </span>
                      {ban.count > 1 && <span className="text-[10px] text-muted-foreground">({ban.count}x)</span>}
                    </div>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={async () => {
                        try {
                          await api.removeBan(ban.ip)
                          api.getBans().then(d => setBans(d.bans || []))
                        } catch (err) { setError(err instanceof Error ? err.message : 'Unban failed') }
                      }}
                    >
                      <X className="h-3 w-3" /> Unban
                    </Button>
                  </div>
                ))}
              </div>
            ) : (
              <span className="text-xs text-muted-foreground">No active temporary bans</span>
            )}
          </div>
        </div>
      </Section>

      {/* Request Sanitizer */}
      <Section
        title="Request Sanitizer"
        badge={{ on: val('sanitizer.enabled', false) as boolean }}
      >
        <div className="space-y-4">
          <FieldRow label="Enabled">
            <Switch
              checked={val('sanitizer.enabled', false) as boolean}
              onCheckedChange={(v) => update('sanitizer.enabled', v)}
            />
          </FieldRow>
          <FieldRow label="Max URL Length">
            <Input
              type="number"
              value={val('sanitizer.max_url_length', 2048) as number}
              onChange={(e) =>
                update('sanitizer.max_url_length', Number(e.target.value))
              }
              className="w-28"
              min={256}
            />
          </FieldRow>
          <FieldRow label="Max Body Size">
            <Input
              type="number"
              value={val('sanitizer.max_body_size', 1048576) as number}
              onChange={(e) =>
                update('sanitizer.max_body_size', Number(e.target.value))
              }
              className="w-32"
              min={1024}
            />
          </FieldRow>
        </div>
      </Section>

      {/* Response Protection */}
      <Section
        title="Response Protection"
        badge={{ on: val('response.security_headers.enabled', false) as boolean }}
      >
        <div className="space-y-4">
          <FieldRow label="Security Headers">
            <Switch
              checked={val('response.security_headers.enabled', false) as boolean}
              onCheckedChange={(v) => update('response.security_headers.enabled', v)}
            />
          </FieldRow>
          <FieldRow label="Data Masking">
            <Switch
              checked={val('response.data_masking.enabled', false) as boolean}
              onCheckedChange={(v) => update('response.data_masking.enabled', v)}
            />
          </FieldRow>
          <FieldRow label="Mask Credit Cards">
            <Switch
              checked={val('response.data_masking.mask_credit_cards', false) as boolean}
              onCheckedChange={(v) => update('response.data_masking.mask_credit_cards', v)}
            />
          </FieldRow>
          <FieldRow label="Mask SSN">
            <Switch
              checked={val('response.data_masking.mask_ssn', false) as boolean}
              onCheckedChange={(v) => update('response.data_masking.mask_ssn', v)}
            />
          </FieldRow>
          <FieldRow label="Mask API Keys">
            <Switch
              checked={val('response.data_masking.mask_api_keys', false) as boolean}
              onCheckedChange={(v) => update('response.data_masking.mask_api_keys', v)}
            />
          </FieldRow>
          <FieldRow label="Strip Stack Traces">
            <Switch
              checked={val('response.data_masking.strip_stack_traces', false) as boolean}
              onCheckedChange={(v) => update('response.data_masking.strip_stack_traces', v)}
            />
          </FieldRow>
        </div>
      </Section>

      {/* CORS Security */}
      <Section
        title="CORS Security"
        badge={{ on: val('cors.enabled', false) as boolean }}
      >
        <div className="space-y-4">
          <FieldRow label="Enabled">
            <Switch
              checked={val('cors.enabled', false) as boolean}
              onCheckedChange={(v) => update('cors.enabled', v)}
            />
          </FieldRow>
          <FieldRow label="Strict Mode">
            <Switch
              checked={val('cors.strict_mode', false) as boolean}
              onCheckedChange={(v) => update('cors.strict_mode', v)}
            />
          </FieldRow>
          <FieldRow label="Allow Credentials">
            <Switch
              checked={val('cors.allow_credentials', false) as boolean}
              onCheckedChange={(v) => update('cors.allow_credentials', v)}
            />
          </FieldRow>
          <div className="text-xs text-muted-foreground mt-2">
            Configure allowed origins, methods, and headers in guardianwaf.yaml
          </div>
        </div>
      </Section>

      {/* Threat Intelligence */}
      <Section
        title="Threat Intelligence"
        badge={{ on: val('threat_intel.enabled', false) as boolean }}
      >
        <div className="space-y-4">
          <FieldRow label="Enabled">
            <Switch
              checked={val('threat_intel.enabled', false) as boolean}
              onCheckedChange={(v) => update('threat_intel.enabled', v)}
            />
          </FieldRow>

          <div className="border-t border-border pt-4 mt-4">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
              IP Reputation
            </h4>
            <div className="space-y-3">
              <FieldRow label="IP Reputation Enabled">
                <Switch
                  checked={val('threat_intel.ip_reputation.enabled', false) as boolean}
                  onCheckedChange={(v) => update('threat_intel.ip_reputation.enabled', v)}
                />
              </FieldRow>
              <FieldRow label="Block Malicious IPs">
                <Switch
                  checked={val('threat_intel.ip_reputation.block_malicious', false) as boolean}
                  onCheckedChange={(v) => update('threat_intel.ip_reputation.block_malicious', v)}
                />
              </FieldRow>
              <FieldRow label="Score Threshold">
                <Input
                  type="number"
                  value={val('threat_intel.ip_reputation.score_threshold', 70) as number}
                  onChange={(e) => update('threat_intel.ip_reputation.score_threshold', Number(e.target.value))}
                  className="w-20"
                  min={0}
                  max={100}
                />
              </FieldRow>
            </div>
          </div>

          <div className="border-t border-border pt-4">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
              Domain Reputation
            </h4>
            <div className="space-y-3">
              <FieldRow label="Domain Reputation Enabled">
                <Switch
                  checked={val('threat_intel.domain_reputation.enabled', false) as boolean}
                  onCheckedChange={(v) => update('threat_intel.domain_reputation.enabled', v)}
                />
              </FieldRow>
              <FieldRow label="Block Malicious Domains">
                <Switch
                  checked={val('threat_intel.domain_reputation.block_malicious', false) as boolean}
                  onCheckedChange={(v) => update('threat_intel.domain_reputation.block_malicious', v)}
                />
              </FieldRow>
            </div>
          </div>
        </div>
      </Section>

      {/* ATO Protection */}
      <Section
        title="ATO Protection"
        badge={{ on: val('ato_protection.enabled', false) as boolean }}
      >
        <div className="space-y-4">
          <FieldRow label="Enabled">
            <Switch
              checked={val('ato_protection.enabled', false) as boolean}
              onCheckedChange={(v) => update('ato_protection.enabled', v)}
            />
          </FieldRow>

          <div className="border-t border-border pt-4 mt-4">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
              Brute Force Detection
            </h4>
            <div className="space-y-3">
              <FieldRow label="Brute Force Enabled">
                <Switch
                  checked={val('ato_protection.brute_force.enabled', false) as boolean}
                  onCheckedChange={(v) => update('ato_protection.brute_force.enabled', v)}
                />
              </FieldRow>
              <FieldRow label="Max Attempts Per IP">
                <Input
                  type="number"
                  value={val('ato_protection.brute_force.max_attempts_per_ip', 10) as number}
                  onChange={(e) => update('ato_protection.brute_force.max_attempts_per_ip', Number(e.target.value))}
                  className="w-20"
                  min={1}
                />
              </FieldRow>
              <FieldRow label="Max Attempts Per Email">
                <Input
                  type="number"
                  value={val('ato_protection.brute_force.max_attempts_per_email', 5) as number}
                  onChange={(e) => update('ato_protection.brute_force.max_attempts_per_email', Number(e.target.value))}
                  className="w-20"
                  min={1}
                />
              </FieldRow>
            </div>
          </div>

          <div className="border-t border-border pt-4">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
              Credential Stuffing
            </h4>
            <div className="space-y-3">
              <FieldRow label="Credential Stuffing Enabled">
                <Switch
                  checked={val('ato_protection.credential_stuffing.enabled', false) as boolean}
                  onCheckedChange={(v) => update('ato_protection.credential_stuffing.enabled', v)}
                />
              </FieldRow>
              <FieldRow label="Distributed Threshold">
                <Input
                  type="number"
                  value={val('ato_protection.credential_stuffing.distributed_threshold', 5) as number}
                  onChange={(e) => update('ato_protection.credential_stuffing.distributed_threshold', Number(e.target.value))}
                  className="w-20"
                  min={2}
                />
              </FieldRow>
            </div>
          </div>

          <div className="border-t border-border pt-4">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
              Impossible Travel
            </h4>
            <div className="space-y-3">
              <FieldRow label="Impossible Travel Enabled">
                <Switch
                  checked={val('ato_protection.impossible_travel.enabled', false) as boolean}
                  onCheckedChange={(v) => update('ato_protection.impossible_travel.enabled', v)}
                />
              </FieldRow>
              <FieldRow label="Max Distance (km)">
                <Input
                  type="number"
                  value={val('ato_protection.impossible_travel.max_distance_km', 500) as number}
                  onChange={(e) => update('ato_protection.impossible_travel.max_distance_km', Number(e.target.value))}
                  className="w-24"
                  min={1}
                />
              </FieldRow>
            </div>
          </div>
        </div>
      </Section>

      {/* API Security */}
      <Section
        title="API Security"
        badge={{ on: val('api_security.enabled', false) as boolean }}
      >
        <div className="space-y-4">
          <FieldRow label="Enabled">
            <Switch
              checked={val('api_security.enabled', false) as boolean}
              onCheckedChange={(v) => update('api_security.enabled', v)}
            />
          </FieldRow>

          <div className="border-t border-border pt-4 mt-4">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
              JWT Validation
            </h4>
            <div className="space-y-3">
              <FieldRow label="JWT Enabled">
                <Switch
                  checked={val('api_security.jwt.enabled', false) as boolean}
                  onCheckedChange={(v) => update('api_security.jwt.enabled', v)}
                />
              </FieldRow>
              <FieldRow label="Issuer">
                <Input
                  value={val('api_security.jwt.issuer', '') as string}
                  onChange={(e) => update('api_security.jwt.issuer', e.target.value)}
                  className="w-64"
                  placeholder="https://auth.example.com"
                />
              </FieldRow>
              <FieldRow label="Audience">
                <Input
                  value={val('api_security.jwt.audience', '') as string}
                  onChange={(e) => update('api_security.jwt.audience', e.target.value)}
                  className="w-64"
                  placeholder="api.example.com"
                />
              </FieldRow>
            </div>
          </div>

          <div className="border-t border-border pt-4">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
              API Keys
            </h4>
            <div className="space-y-3">
              <FieldRow label="API Keys Enabled">
                <Switch
                  checked={val('api_security.api_keys.enabled', false) as boolean}
                  onCheckedChange={(v) => update('api_security.api_keys.enabled', v)}
                />
              </FieldRow>
              <FieldRow label="Header Name">
                <Input
                  value={val('api_security.api_keys.header_name', 'X-API-Key') as string}
                  onChange={(e) => update('api_security.api_keys.header_name', e.target.value)}
                  className="w-40"
                  placeholder="X-API-Key"
                />
              </FieldRow>
              <div className="text-xs text-muted-foreground">
                Configured API Keys: {val('api_security.api_keys.key_count', 0) as number}
              </div>
            </div>
          </div>
        </div>
      </Section>

      {/* Sticky Save Bar */}
      {dirty && (
        <div className="fixed bottom-0 left-0 right-0 z-50 border-t border-border bg-card/95 backdrop-blur-sm">
          <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-3">
            <span className="text-sm text-muted-foreground">
              You have unsaved changes
            </span>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              Save &amp; Apply
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

/* ---------- Helper Components ---------- */

function FieldRow({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <label className="text-sm text-foreground whitespace-nowrap">{label}</label>
      {children}
    </div>
  )
}

function IPChip({
  ip,
  variant = 'default',
  onRemove,
}: {
  ip: string
  variant?: 'default' | 'destructive'
  onRemove: () => void
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-mono',
        variant === 'destructive'
          ? 'border-destructive/30 bg-destructive/10 text-destructive'
          : 'border-accent/30 bg-accent/10 text-accent',
      )}
    >
      {ip}
      <button
        type="button"
        onClick={onRemove}
        className="rounded-full p-0.5 transition-colors hover:bg-foreground/10"
        aria-label={`Remove ${ip}`}
      >
        <X className="h-3 w-3" />
      </button>
    </span>
  )
}
