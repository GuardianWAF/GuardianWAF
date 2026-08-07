import { useState, useCallback } from 'react'
import { Mail, Webhook, Plus, Trash2, TestTube, AlertCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { api, AlertingStatusResponse, WebhookConfig, EmailConfig } from '@/lib/api'
import { useToast } from '@/components/ui/toast'
import { useMountLoad } from '@/hooks/use-mount-load'
import { cn } from '@/lib/utils'

export default function AlertingPage() {
  const [status, setStatus] = useState<AlertingStatusResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'webhooks' | 'emails'>('webhooks')
  const { toast } = useToast()

  // New webhook form
  const [newWebhook, setNewWebhook] = useState<Partial<WebhookConfig>>({
    type: 'generic',
    events: ['block'],
    min_score: 50,
    cooldown: '30s',
  })

  // New email form
  const [newEmail, setNewEmail] = useState<Partial<EmailConfig>>({
    smtp_port: 587,
    use_tls: true,
    events: ['block'],
    min_score: 50,
    cooldown: '5m',
    to: [],
  })

  // Declared before the hook that calls it: referencing it earlier relied on
  // the effect running after the whole body had evaluated.
  const fetchStatus = useCallback(async (isCancelled: () => boolean = () => false) => {
    setLoading(true)
    try {
      const res = await api.getAlertingStatus()
      if (isCancelled()) return
      setStatus(res)
      setError(null)
    } catch (err: unknown) {
      if (!isCancelled()) setError(err instanceof Error ? err.message : 'Failed to fetch alerting status')
    } finally {
      if (!isCancelled()) setLoading(false)
    }
  }, [])

  useMountLoad(fetchStatus)

  const addWebhook = async () => {
    if (!newWebhook.name || !newWebhook.url) {
      setError('Name and URL are required')
      return
    }
    try {
      await api.addWebhook(newWebhook as WebhookConfig)
      setNewWebhook({ type: 'generic', events: ['block'], min_score: 50, cooldown: '30s' })
      fetchStatus()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to add webhook')
    }
  }

  const removeWebhook = async (name: string) => {
    try {
      await api.deleteWebhook(name)
      fetchStatus()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to remove webhook')
    }
  }

  const addEmail = async () => {
    if (!newEmail.name || !newEmail.smtp_host || !newEmail.from || !newEmail.to?.length) {
      setError('Name, SMTP host, From, and To are required')
      return
    }
    try {
      await api.addEmail(newEmail as EmailConfig)
      setNewEmail({ smtp_port: 587, use_tls: true, events: ['block'], min_score: 50, cooldown: '5m', to: [] })
      fetchStatus()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to add email target')
    }
  }

  const removeEmail = async (name: string) => {
    try {
      await api.deleteEmail(name)
      fetchStatus()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to remove email target')
    }
  }

  const testAlert = async (target: string) => {
    try {
      await api.testAlert(target)
      toast({ title: 'Test sent', description: `Test alert sent to ${target}` })
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to send test alert')
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin h-8 w-8 border-2 border-accent border-t-transparent rounded-full" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Alerting</h1>
          <p className="text-muted-foreground mt-1">
            Configure webhooks and email notifications for security events
          </p>
        </div>
        {status && (
          <div className="flex items-center gap-4 text-sm">
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">Sent:</span>
              <span className="font-medium text-green-600">{status.sent || 0}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">Failed:</span>
              <span className="font-medium text-red-600">{status.failed || 0}</span>
            </div>
          </div>
        )}
      </div>

      {/* Error Banner */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-center gap-3">
          <AlertCircle className="h-5 w-5 text-red-600" />
          <div>
            <p className="font-medium text-red-800">Error</p>
            <p className="text-sm text-red-700">{error}</p>
          </div>
          <button
            onClick={() => setError(null)}
            className="ml-auto text-sm text-red-600 hover:text-red-800"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Status Banner */}
      {!status?.enabled && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 flex items-center gap-3">
          <AlertCircle className="h-5 w-5 text-yellow-600" />
          <div>
            <p className="font-medium text-yellow-800">Alerting is disabled</p>
            <p className="text-sm text-yellow-700">
              Enable alerting in your configuration file to start receiving notifications
            </p>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-2 border-b border-border">
        <button
          onClick={() => setActiveTab('webhooks')}
          className={cn(
            'flex items-center gap-2 px-4 py-2 text-sm font-medium transition-colors',
            activeTab === 'webhooks'
              ? 'text-accent border-b-2 border-accent'
              : 'text-muted-foreground hover:text-foreground'
          )}
        >
          <Webhook className="h-4 w-4" />
          Webhooks
          <Badge variant="secondary" className="ml-1">{status?.webhooks?.length || 0}</Badge>
        </button>
        <button
          onClick={() => setActiveTab('emails')}
          className={cn(
            'flex items-center gap-2 px-4 py-2 text-sm font-medium transition-colors',
            activeTab === 'emails'
              ? 'text-accent border-b-2 border-accent'
              : 'text-muted-foreground hover:text-foreground'
          )}
        >
          <Mail className="h-4 w-4" />
          Email
          <Badge variant="secondary" className="ml-1">{status?.emails?.length || 0}</Badge>
        </button>
      </div>

      {/* Webhooks Tab */}
      {activeTab === 'webhooks' && (
        <div className="space-y-6">
          {/* Add Webhook Form */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Plus className="h-5 w-5" />
                Add Webhook
              </CardTitle>
              <CardDescription>
                Add a new webhook endpoint to receive security event notifications
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Name</label>
                  <Input
                    placeholder="slack-alerts"
                    value={newWebhook.name || ''}
                    onChange={(e) => setNewWebhook({ ...newWebhook, name: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">URL</label>
                  <Input
                    placeholder="https://hooks.slack.com/services/..."
                    value={newWebhook.url || ''}
                    onChange={(e) => setNewWebhook({ ...newWebhook, url: e.target.value })}
                  />
                </div>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Type</label>
                  <select
                    className="w-full h-10 px-3 rounded-md border border-input bg-background"
                    value={newWebhook.type}
                    onChange={(e) => setNewWebhook({ ...newWebhook, type: e.target.value as WebhookConfig['type'] })}
                  >
                    <option value="generic">Generic</option>
                    <option value="slack">Slack</option>
                    <option value="discord">Discord</option>
                    <option value="pagerduty">PagerDuty</option>
                  </select>
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Min Score</label>
                  <Input
                    type="number"
                    min={0}
                    max={100}
                    value={newWebhook.min_score}
                    onChange={(e) => setNewWebhook({ ...newWebhook, min_score: parseInt(e.target.value) })}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Cooldown</label>
                  <Input
                    placeholder="30s"
                    value={newWebhook.cooldown}
                    onChange={(e) => setNewWebhook({ ...newWebhook, cooldown: e.target.value })}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Events</label>
                <div className="flex gap-4">
                  {['block', 'challenge', 'log', 'all'].map((event) => (
                    <label key={event} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        className="rounded border-input"
                        checked={newWebhook.events?.includes(event)}
                        onChange={(e) => {
                          const events = e.target.checked
                            ? [...(newWebhook.events || []), event]
                            : (newWebhook.events || []).filter((ev) => ev !== event)
                          setNewWebhook({ ...newWebhook, events })
                        }}
                      />
                      <span className="text-sm capitalize">{event}</span>
                    </label>
                  ))}
                </div>
              </div>
              <Button onClick={addWebhook} className="w-full">
                <Plus className="h-4 w-4 mr-2" />
                Add Webhook
              </Button>
            </CardContent>
          </Card>

          {/* Webhooks List */}
          {status?.webhooks && status.webhooks.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Configured Webhooks</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {status.webhooks.map((webhook) => (
                    <div
                      key={webhook.name}
                      className="flex items-center justify-between p-4 border border-border rounded-lg"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{webhook.name}</span>
                          <Badge variant="outline" className="capitalize">{webhook.type}</Badge>
                        </div>
                        <p className="text-sm text-muted-foreground">{webhook.url}</p>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          <span>Min score: {webhook.min_score}</span>
                          <span>Cooldown: {webhook.cooldown}</span>
                          <span>Events: {webhook.events.join(', ')}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => testAlert(webhook.name)}
                          title="Send test alert"
                        >
                          <TestTube className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => removeWebhook(webhook.name)}
                          className="text-red-600 hover:text-red-700"
                          title="Remove webhook"
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Emails Tab */}
      {activeTab === 'emails' && (
        <div className="space-y-6">
          {/* Add Email Form */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Plus className="h-5 w-5" />
                Add Email Target
              </CardTitle>
              <CardDescription>
                Add a new SMTP email configuration for security alerts
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Name</label>
                  <Input
                    placeholder="admin-alerts"
                    value={newEmail.name || ''}
                    onChange={(e) => setNewEmail({ ...newEmail, name: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">SMTP Host</label>
                  <Input
                    placeholder="smtp.gmail.com"
                    value={newEmail.smtp_host || ''}
                    onChange={(e) => setNewEmail({ ...newEmail, smtp_host: e.target.value })}
                  />
                </div>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">SMTP Port</label>
                  <Input
                    type="number"
                    value={newEmail.smtp_port}
                    onChange={(e) => setNewEmail({ ...newEmail, smtp_port: parseInt(e.target.value) })}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Username</label>
                  <Input
                    placeholder="optional"
                    value={newEmail.username || ''}
                    onChange={(e) => setNewEmail({ ...newEmail, username: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Password</label>
                  <Input
                    type="password"
                    placeholder="optional"
                    value={newEmail.password || ''}
                    onChange={(e) => setNewEmail({ ...newEmail, password: e.target.value })}
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">From</label>
                  <Input
                    placeholder="alerts@example.com"
                    value={newEmail.from || ''}
                    onChange={(e) => setNewEmail({ ...newEmail, from: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">To (comma-separated)</label>
                  <Input
                    placeholder="admin@example.com, security@example.com"
                    value={newEmail.to?.join(', ') || ''}
                    onChange={(e) => setNewEmail({ ...newEmail, to: e.target.value.split(',').map(s => s.trim()).filter(Boolean) })}
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Min Score</label>
                  <Input
                    type="number"
                    min={0}
                    max={100}
                    value={newEmail.min_score}
                    onChange={(e) => setNewEmail({ ...newEmail, min_score: parseInt(e.target.value) })}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Cooldown</label>
                  <Input
                    placeholder="5m"
                    value={newEmail.cooldown}
                    onChange={(e) => setNewEmail({ ...newEmail, cooldown: e.target.value })}
                  />
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Switch
                  checked={newEmail.use_tls}
                  onCheckedChange={(checked) => setNewEmail({ ...newEmail, use_tls: checked })}
                />
                <label className="text-sm font-medium">Use TLS</label>
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">Events</label>
                <div className="flex gap-4">
                  {['block', 'challenge', 'log', 'all'].map((event) => (
                    <label key={event} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        className="rounded border-input"
                        checked={newEmail.events?.includes(event)}
                        onChange={(e) => {
                          const events = e.target.checked
                            ? [...(newEmail.events || []), event]
                            : (newEmail.events || []).filter((ev) => ev !== event)
                          setNewEmail({ ...newEmail, events })
                        }}
                      />
                      <span className="text-sm capitalize">{event}</span>
                    </label>
                  ))}
                </div>
              </div>
              <Button onClick={addEmail} className="w-full">
                <Plus className="h-4 w-4 mr-2" />
                Add Email Target
              </Button>
            </CardContent>
          </Card>

          {/* Emails List */}
          {status?.emails && status.emails.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Configured Email Targets</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {status.emails.map((email) => (
                    <div
                      key={email.name}
                      className="flex items-center justify-between p-4 border border-border rounded-lg"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{email.name}</span>
                          {email.use_tls && <Badge variant="outline">TLS</Badge>}
                        </div>
                        <p className="text-sm text-muted-foreground">
                          {email.smtp_host}:{email.smtp_port}
                        </p>
                        <p className="text-sm text-muted-foreground">
                          From: {email.from} → To: {email.to.join(', ')}
                        </p>
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          <span>Min score: {email.min_score}</span>
                          <span>Cooldown: {email.cooldown}</span>
                          <span>Events: {email.events.join(', ')}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => testAlert(email.name)}
                          title="Send test alert"
                        >
                          <TestTube className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => removeEmail(email.name)}
                          className="text-red-600 hover:text-red-700"
                          title="Remove email target"
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}
