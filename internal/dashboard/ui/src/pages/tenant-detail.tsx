import { useState, useEffect } from 'react'

import { useParams, useNavigate } from 'react-router'

import { Button } from '@/components/ui/button'

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

import { Input } from '@/components/ui/input'

import { Label } from '@/components/ui/label'

import { Select, SelectOption } from '@/components/ui/select'

import { useToast } from '@/components/ui/toast'

import { useFocusTrap } from '@/hooks/use-focus-trap'

import { api, type AdminTenantDetail } from '@/lib/api'

import {

  ArrowLeft,

  Plus,

  Save,

  Trash2,

  RefreshCw,

  Copy,

  Key,

  Shield,

  AlertTriangle,

  Clock,

  CheckCircle,

  X,

  History,

  Eye,

  EyeOff

} from 'lucide-react'

import { Badge } from '@/components/ui/badge'



type Tenant = AdminTenantDetail



interface ApiKeyRotation {

  id: string

  created_at: string

  expires_at?: string

  last_used_at?: string

  is_active: boolean

  rotation_reason?: string

}



const ROTATION_INTERVALS = [

  { value: 'never', label: 'Never (Manual Only)', days: 0 },

  { value: '30days', label: 'Every 30 Days', days: 30 },

  { value: '90days', label: 'Every 90 Days', days: 90 },

  { value: '180days', label: 'Every 180 Days', days: 180 },

  { value: '365days', label: 'Every Year', days: 365 }

]



export default function TenantDetailPage() {

  const { id } = useParams<{ id: string }>()

  const navigate = useNavigate()

  const [loading, setLoading] = useState(true)

  const [saving, setSaving] = useState(false)

  const [tenant, setTenant] = useState<Tenant | null>(null)

  const [showApiKey, setShowApiKey] = useState(false)

  const [newApiKey, setNewApiKey] = useState<string | null>(null)

  const [rotationHistory, setRotationHistory] = useState<ApiKeyRotation[]>([])

  const [autoRotationEnabled, setAutoRotationEnabled] = useState(false)

  const [rotationInterval, setRotationInterval] = useState('90days')

  const [showRotationModal, setShowRotationModal] = useState(false)

  const [rotationReason, setRotationReason] = useState('')

  const { toast } = useToast()



  const [form, setForm] = useState({

    name: '',

    email: '',

    plan: 'basic',

    status: 'active',

    domains: ['']

  })



  useEffect(() => {

    loadTenant()


  }, [id])



  const loadTenant = async () => {

    try {

      const data = await api.adminGetTenant(id!)

      setTenant(data)

      setForm({

        name: data.name || '',

        email: data.email || '',

        plan: data.plan || 'basic',

        status: data.status || 'active',

        domains: data.domains?.length ? data.domains : ['']

      })

    } catch {

      toast({

        title: 'Error',

        description: 'Failed to load tenant',

        variant: 'destructive'

      })

    } finally {

      setLoading(false)

    }

  }
  const handleSave = async () => {

    setSaving(true)

    try {

      await api.adminUpdateTenant(id!, {

        name: form.name,

        email: form.email,

        plan: form.plan,

        status: form.status,

        domains: form.domains.filter(d => d.trim()),

        auto_rotation: autoRotationEnabled,

        rotation_interval: rotationInterval

      })

      toast({ title: 'Success', description: 'Tenant updated' })

      loadTenant()

    } catch (error: unknown) {

      toast({

        title: 'Error',

        description: error instanceof Error ? error.message : 'Failed to update tenant',

        variant: 'destructive'

      })

    } finally {

      setSaving(false)

    }

  }



  const handleRegenerateKey = async () => {

    if (!rotationReason.trim()) {

      setShowRotationModal(true)

      return

    }



    try {

      const response = await api.adminRegenerateKey(id!)

      setNewApiKey(response.api_key)

      setShowRotationModal(false)

      setRotationReason('')



      // Add to rotation history

      const newRotation: ApiKeyRotation = {

        id: `key_${Date.now()}`,

        created_at: new Date().toISOString(),

        is_active: true,

        rotation_reason: rotationReason

      }

      setRotationHistory(prev => [newRotation, ...prev.map(k => ({ ...k, is_active: false }))])



      toast({

        title: 'Success',

        description: 'New API key generated successfully'

      })

    } catch {

      toast({

        title: 'Error',

        description: 'Failed to regenerate API key',

        variant: 'destructive'

      })

    }

  }



  const handleDelete = async () => {

    if (!confirm('Are you sure you want to delete this tenant? This cannot be undone.')) return

    try {

      await api.adminDeleteTenant(id!)

      toast({ title: 'Success', description: 'Tenant deleted' })

      navigate('/tenants')

    } catch {

      toast({

        title: 'Error',

        description: 'Failed to delete tenant',

        variant: 'destructive'

      })

    }

  }



  const addDomain = () => {

    setForm({ ...form, domains: [...form.domains, ''] })

  }



  const removeDomain = (index: number) => {

    const newDomains = form.domains.filter((_, i) => i !== index)

    setForm({ ...form, domains: newDomains.length ? newDomains : [''] })

  }



  const updateDomain = (index: number, value: string) => {

    const newDomains = [...form.domains]

    newDomains[index] = value

    setForm({ ...form, domains: newDomains })

  }



  const copyApiKey = (key: string) => {

    navigator.clipboard.writeText(key)

    toast({ title: 'Copied', description: 'API key copied to clipboard' })

  }



  // Removed downloadCredentials — storing raw API keys in plaintext files is a

  // security risk. Keys are shown exactly once on generation; use clipboard copy

  // or display the key shown on screen for manual recording.



  const getDaysUntilExpiration = (createdAt: string, intervalDays: number) => {

    const created = new Date(createdAt)

    const expires = new Date(created.getTime() + intervalDays * 86400000)

    const now = new Date()

    const diff = expires.getTime() - now.getTime()

    return Math.ceil(diff / 86400000)

  }



  if (loading) {

    return <div className="text-center py-8">Loading...</div>

  }



  if (!tenant) {

    return (

      <div className="max-w-2xl mx-auto text-center py-8">

        <h1 className="text-2xl font-bold mb-4">Tenant Not Found</h1>

        <Button onClick={() => navigate('/tenants')}>

          <ArrowLeft className="w-4 h-4 mr-2" />

          Back to Tenants

        </Button>

      </div>

    )

  }



  return (

    <div className="max-w-4xl mx-auto space-y-6">

      {/* Header */}

      <div className="flex items-center justify-between">

        <div className="flex items-center gap-4">

          <Button variant="ghost" onClick={() => navigate('/tenants')}>

            <ArrowLeft className="w-4 h-4 mr-2" />

            Back

          </Button>

          <h1 className="text-3xl font-bold">{tenant.name}</h1>

          <Badge variant={tenant.status === 'active' ? 'default' : 'secondary'}>

            {tenant.status}

          </Badge>

        </div>

        <div className="flex gap-2">

          <Button variant="outline" onClick={() => navigate(`/tenants/${id}/analytics`)}>

            <History className="w-4 h-4 mr-2" />

            Analytics

          </Button>

          <Button variant="destructive" onClick={handleDelete}>

            <Trash2 className="w-4 h-4 mr-2" />

            Delete

          </Button>

        </div>

      </div>



      {/* New API Key Display */}

      {newApiKey && (

        <Card className="border-yellow-400 bg-yellow-50 dark:bg-yellow-900/20">

          <CardHeader>

            <CardTitle className="flex items-center gap-2 text-yellow-800 dark:text-yellow-200">

              <Key className="w-5 h-5" />

              New API Key Generated - Copy Now!

            </CardTitle>

          </CardHeader>

          <CardContent className="space-y-4">

            <div className="p-4 bg-black rounded-lg">

              <code className="text-green-400 font-mono text-sm break-all">{newApiKey}</code>

            </div>

            <div className="flex gap-2">

              <Button onClick={() => copyApiKey(newApiKey)}>

                <Copy className="w-4 h-4 mr-2" />

                Copy Key

              </Button>

              <Button variant="ghost" onClick={() => setNewApiKey(null)}>

                <X className="w-4 h-4 mr-2" />

                Dismiss

              </Button>

            </div>

            <p className="text-sm text-yellow-800 dark:text-yellow-200">

              <AlertTriangle className="w-4 h-4 inline mr-1" />

              This key will not be shown again. Copy it now and store it in your password manager.

            </p>

          </CardContent>

        </Card>

      )}



      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* Basic Information */}

        <Card>

          <CardHeader>

            <CardTitle>Basic Information</CardTitle>

          </CardHeader>

          <CardContent className="space-y-4">

            <div className="space-y-2">

              <Label htmlFor="name">Company/Organization Name</Label>

              <Input

                id="name"

                value={form.name}

                onChange={(e) => setForm({ ...form, name: e.target.value })}

              />

            </div>



            <div className="space-y-2">

              <Label htmlFor="email">Contact Email</Label>

              <Input

                id="email"

                type="email"

                value={form.email}

                onChange={(e) => setForm({ ...form, email: e.target.value })}

              />

            </div>



            <div className="grid grid-cols-2 gap-4">

              <div className="space-y-2">

                <Label htmlFor="plan">Plan</Label>

                <Select

                  id="plan"

                  value={form.plan}

                  onChange={(e) => setForm({ ...form, plan: e.target.value })}

                >

                  <SelectOption value="free">Free</SelectOption>

                  <SelectOption value="basic">Basic</SelectOption>

                  <SelectOption value="pro">Pro</SelectOption>

                  <SelectOption value="enterprise">Enterprise</SelectOption>

                </Select>

              </div>



              <div className="space-y-2">

                <Label htmlFor="status">Status</Label>

                <Select

                  id="status"

                  value={form.status}

                  onChange={(e) => setForm({ ...form, status: e.target.value })}

                >

                  <SelectOption value="active">Active</SelectOption>

                  <SelectOption value="trial">Trial</SelectOption>

                  <SelectOption value="suspended">Suspended</SelectOption>

                  <SelectOption value="expired">Expired</SelectOption>

                </Select>

              </div>

            </div>

          </CardContent>

        </Card>



        {/* API Key Management */}

        <Card>

          <CardHeader>

            <CardTitle className="flex items-center gap-2">

              <Shield className="w-5 h-5" />

              API Key Management

            </CardTitle>

          </CardHeader>

          <CardContent className="space-y-4">

            <div className="space-y-2">

              <Label>Tenant ID</Label>

              <code className="block p-2 bg-gray-100 dark:bg-gray-800 rounded font-mono text-sm">

                {tenant.id}

              </code>

            </div>



            <div className="space-y-2">

              <Label>Current API Key</Label>

              <div className="flex items-center gap-2">

                <div className="flex-1 relative">

                  <code className="block p-2 bg-gray-100 dark:bg-gray-800 rounded font-mono text-sm truncate">

                    {showApiKey ? tenant.api_key || '***hidden***' : '••••••••••••••••••••••••••••••••'}

                  </code>

                </div>

                <Button

                  variant="outline"

                  size="sm"

                  onClick={() => setShowApiKey(!showApiKey)}

                >

                  {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}

                </Button>

                <Button variant="outline" size="sm" onClick={() => tenant.api_key && copyApiKey(tenant.api_key)}>

                  <Copy className="w-4 h-4" />

                </Button>

              </div>

            </div>



            <div className="border-t pt-4 space-y-4">

              <div className="flex items-center justify-between">

                <div>

                  <div className="font-medium">Auto Key Rotation</div>

                  <div className="text-sm text-gray-500">Automatically rotate keys periodically</div>

                </div>

                <button

                  onClick={() => setAutoRotationEnabled(!autoRotationEnabled)}

                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${

                    autoRotationEnabled ? 'bg-accent' : 'bg-gray-200 dark:bg-gray-700'

                  }`}

                >

                  <span

                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${

                      autoRotationEnabled ? 'translate-x-6' : 'translate-x-1'

                    }`}

                  />

                </button>

              </div>



              {autoRotationEnabled && (

                <div className="space-y-2">

                  <Label>Rotation Interval</Label>

                  <Select

                    value={rotationInterval}

                    onChange={(e) => setRotationInterval(e.target.value)}

                  >

                    {ROTATION_INTERVALS.map(interval => (

                      <SelectOption key={interval.value} value={interval.value}>

                        {interval.label}

                      </SelectOption>

                    ))}

                  </Select>

                  <p className="text-xs text-gray-500">

                    A new key will be generated and the old key will expire after this period.

                  </p>

                </div>

              )}



              <Button

                variant="outline"

                className="w-full"

                onClick={() => setShowRotationModal(true)}

              >

                <RefreshCw className="w-4 h-4 mr-2" />

                Rotate API Key Now

              </Button>

            </div>

          </CardContent>

        </Card>

      </div>



      {/* Key Rotation History */}

      <Card>

        <CardHeader>

          <CardTitle className="flex items-center gap-2">

            <History className="w-5 h-5" />

            API Key Rotation History

          </CardTitle>

        </CardHeader>

        <CardContent>

          <div className="overflow-x-auto">

            <table className="w-full">

              <caption className="sr-only">API key rotation history with key ID, created date, status, reason, and expiration columns</caption>

              <thead>

                <tr className="border-b border-gray-200 dark:border-gray-700">

                  <th scope="col" className="text-left py-3 px-4 font-medium">Key ID</th>

                  <th scope="col" className="text-left py-3 px-4 font-medium">Created</th>

                  <th scope="col" className="text-left py-3 px-4 font-medium">Status</th>

                  <th scope="col" className="text-left py-3 px-4 font-medium">Reason</th>

                  <th scope="col" className="text-left py-3 px-4 font-medium">Expiration</th>

                </tr>

              </thead>

              <tbody>

                {rotationHistory.length === 0 && (
                  <tr>
                    <td colSpan={4} className="py-8 text-center text-gray-500">
                      No key rotation history. Rotate the API key to create a record.
                    </td>
                  </tr>
                )}
                {rotationHistory.map((key) => {

                  const intervalDays = ROTATION_INTERVALS.find(i => i.value === rotationInterval)?.days || 90

                  const daysLeft = autoRotationEnabled ? getDaysUntilExpiration(key.created_at, intervalDays) : null



                  return (

                    <tr key={key.id} className="border-b border-gray-100 dark:border-gray-800">

                      <td className="py-3 px-4 font-mono text-sm">{key.id}</td>

                      <td className="py-3 px-4 text-sm">

                        {new Date(key.created_at).toLocaleDateString()}

                      </td>

                      <td className="py-3 px-4">

                        {key.is_active ? (

                          <Badge className="bg-green-500 flex items-center gap-1 w-fit">

                            <CheckCircle className="w-3 h-3" />

                            Active

                          </Badge>

                        ) : (

                          <Badge variant="outline" className="flex items-center gap-1 w-fit">

                            <Clock className="w-3 h-3" />

                            Expired

                          </Badge>

                        )}

                      </td>

                      <td className="py-3 px-4 text-sm text-gray-600">

                        {key.rotation_reason || 'Manual rotation'}

                      </td>

                      <td className="py-3 px-4 text-sm">

                        {key.is_active && autoRotationEnabled && daysLeft !== null ? (

                          daysLeft <= 7 ? (

                            <span className="text-red-600 flex items-center gap-1">

                              <AlertTriangle className="w-3 h-3" />

                              {daysLeft} days

                            </span>

                          ) : (

                            <span className="text-gray-500">{daysLeft} days</span>

                          )

                        ) : (

                          <span className="text-gray-400">-</span>

                        )}

                      </td>

                    </tr>

                  )

                })}

              </tbody>

            </table>

          </div>

        </CardContent>

      </Card>



      {/* Domains */}

      <Card>

        <CardHeader>

          <CardTitle>Domains</CardTitle>

        </CardHeader>

        <CardContent className="space-y-4">

          {form.domains.map((domain, index) => (

            <div key={index} className="flex items-center gap-2">

              <Input

                value={domain}

                onChange={(e) => updateDomain(index, e.target.value)}

                placeholder="example.com"

              />

              {form.domains.length > 1 && (

                <Button

                  type="button"

                  variant="ghost"

                  size="sm"

                  onClick={() => removeDomain(index)}

                >

                  Remove

                </Button>

              )}

            </div>

          ))}

          <Button type="button" variant="outline" onClick={addDomain} className="w-full">

            <Plus className="w-4 h-4 mr-2" />

            Add Domain

          </Button>

        </CardContent>

      </Card>



      {/* Resource Quota */}

      <Card>

        <CardHeader>

          <CardTitle>Resource Quota</CardTitle>

        </CardHeader>

        <CardContent>

          <div className="grid grid-cols-3 md:grid-cols-6 gap-4 text-center">

            <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded">

              <div className="text-2xl font-bold">{tenant.quota?.max_domains || 0}</div>

              <div className="text-sm text-gray-500">Domains</div>

            </div>

            <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded">

              <div className="text-2xl font-bold">{tenant.quota?.max_rules || 0}</div>

              <div className="text-sm text-gray-500">Rules</div>

            </div>

            <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded">

              <div className="text-2xl font-bold">{tenant.quota?.max_rate_limit_rules || 0}</div>

              <div className="text-sm text-gray-500">Rate Limits</div>

            </div>

            <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded">

              <div className="text-2xl font-bold">

                {(tenant.quota?.max_requests_per_minute || 0).toLocaleString()}

              </div>

              <div className="text-sm text-gray-500">Reqs/Min</div>

            </div>

            <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded">

              <div className="text-2xl font-bold">{tenant.quota?.max_bandwidth_mbps || 0}</div>

              <div className="text-sm text-gray-500">Mbps</div>

            </div>

            <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded">

              <div className="text-2xl font-bold">{tenant.quota?.max_ip_acls || 0}</div>

              <div className="text-sm text-gray-500">IP ACLs</div>

            </div>

          </div>

        </CardContent>

      </Card>



      {/* Usage Statistics */}

      <Card>

        <CardHeader>

          <CardTitle>Usage Statistics</CardTitle>

        </CardHeader>

        <CardContent>

          <div className="grid grid-cols-2 gap-4 text-center">

            <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded">

              <div className="text-3xl font-bold text-blue-600">

                {tenant.usage?.requests_this_month?.toLocaleString() || 0}

              </div>

              <div className="text-sm text-gray-500">Requests This Month</div>

            </div>

            <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded">

              <div className="text-3xl font-bold text-red-600">

                {tenant.usage?.blocked_requests?.toLocaleString() || 0}

              </div>

              <div className="text-sm text-gray-500">Blocked Requests</div>

            </div>

          </div>

        </CardContent>

      </Card>



      {/* Save Button */}

      <div className="flex justify-end gap-4">

        <Button variant="outline" onClick={() => navigate('/tenants')}>

          Cancel

        </Button>

        <Button onClick={handleSave} disabled={saving}>

          <Save className="w-4 h-4 mr-2" />

          {saving ? 'Saving...' : 'Save Changes'}

        </Button>

      </div>



      {/* Rotation Modal */}

      {showRotationModal && (

        <RotationModalFocusTrap onClose={() => setShowRotationModal(false)}>

          <Card className="w-full max-w-md mx-4">

            <CardHeader>

              <CardTitle className="flex items-center gap-2">

                <AlertTriangle className="w-5 h-5 text-yellow-500" />

                Rotate API Key

              </CardTitle>

            </CardHeader>

            <CardContent className="space-y-4">

              <p className="text-sm text-gray-600 dark:text-gray-400">

                This will generate a new API key and invalidate the current one.

                Make sure to update any applications using this key immediately.

              </p>

              <div className="space-y-2">

                <Label htmlFor="rotation-reason">Rotation Reason (Required)</Label>

                <Input

                  id="rotation-reason"

                  placeholder="e.g., Security incident, Quarterly rotation, etc."

                  value={rotationReason}

                  onChange={(e) => setRotationReason(e.target.value)}

                />

              </div>

              <div className="flex gap-2 pt-2">

                <Button variant="outline" className="flex-1" onClick={() => setShowRotationModal(false)}>

                  Cancel

                </Button>

                <Button

                  className="flex-1"

                  onClick={handleRegenerateKey}

                  disabled={!rotationReason.trim()}

                >

                  <RefreshCw className="w-4 h-4 mr-2" />

                  Rotate Key

                </Button>

              </div>

            </CardContent>

          </Card>

        </RotationModalFocusTrap>

      )}

    </div>

  )

}



function RotationModalFocusTrap({ onClose, children }: { onClose: () => void; children: React.ReactNode }) {

  const trapRef = useFocusTrap(onClose)

  return (

    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={onClose}>

      <div ref={trapRef} tabIndex={-1} role="dialog" aria-modal="true" aria-label="Rotate API key" className="outline-none" onClick={e => e.stopPropagation()}>

        {children}

      </div>

    </div>

  )

}

