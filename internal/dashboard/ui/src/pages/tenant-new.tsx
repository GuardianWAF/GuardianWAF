import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useToast } from '@/components/ui/toast'
import { api } from '@/lib/api'
import {
  ArrowLeft,
  ArrowRight,
  Check,
  Copy,
  Globe,
  Building2,
  Key,
  Sparkles,
  Shield,
  Zap,
  Server,
  Download
} from 'lucide-react'

type Step = 1 | 2 | 3 | 4 | 5

interface Plan {
  id: string
  name: string
  price: string
  description: string
  icon: React.ElementType
  features: string[]
  quota: QuotaConfig
  recommended?: boolean
}

interface QuotaConfig {
  max_domains: number
  max_rules: number
  max_rate_limit_rules: number
  max_requests_per_minute: number
  max_bandwidth_mbps: number
  max_ip_acls?: number
}

const PLANS: Plan[] = [
  {
    id: 'free',
    name: 'Free',
    price: '$0',
    description: 'Perfect for testing and small projects',
    icon: Sparkles,
    features: ['1 Domain', '5 Custom Rules', '1,000 req/min', '10 Mbps bandwidth', 'Community support'],
    quota: {
      max_domains: 1,
      max_rules: 5,
      max_rate_limit_rules: 2,
      max_requests_per_minute: 1000,
      max_bandwidth_mbps: 10,
      max_ip_acls: 10
    }
  },
  {
    id: 'basic',
    name: 'Basic',
    price: '$49',
    description: 'For small businesses getting started',
    icon: Shield,
    recommended: true,
    features: ['3 Domains', '20 Custom Rules', '10,000 req/min', '100 Mbps bandwidth', 'Email support'],
    quota: {
      max_domains: 3,
      max_rules: 20,
      max_rate_limit_rules: 5,
      max_requests_per_minute: 10000,
      max_bandwidth_mbps: 100,
      max_ip_acls: 50
    }
  },
  {
    id: 'pro',
    name: 'Pro',
    price: '$199',
    description: 'For growing businesses with high traffic',
    icon: Zap,
    features: ['10 Domains', '100 Custom Rules', '50,000 req/min', '1 Gbps bandwidth', 'Priority support', 'Advanced analytics'],
    quota: {
      max_domains: 10,
      max_rules: 100,
      max_rate_limit_rules: 20,
      max_requests_per_minute: 50000,
      max_bandwidth_mbps: 1000,
      max_ip_acls: 200
    }
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    price: 'Custom',
    description: 'For large organizations with custom needs',
    icon: Server,
    features: ['Unlimited Domains', 'Unlimited Rules', 'Custom req/min', 'Custom bandwidth', '24/7 Phone support', 'Dedicated account manager', 'SLA guarantee'],
    quota: {
      max_domains: 100,
      max_rules: 1000,
      max_rate_limit_rules: 100,
      max_requests_per_minute: 100000,
      max_bandwidth_mbps: 10000,
      max_ip_acls: 1000
    }
  }
]

interface CreateResponse {
  tenant: {
    id: string
    name: string
    created_at: string
  }
  api_key: string
}

export default function TenantNewPage() {
  const [step, setStep] = useState<Step>(1)
  const [loading, setLoading] = useState(false)
  const [, setCreated] = useState(false)
  const [apiKey, setApiKey] = useState('')
  const [tenantId, setTenantId] = useState('')
  const { toast } = useToast()

  const [form, setForm] = useState({
    name: '',
    email: '',
    description: '',
    plan: 'basic',
    domains: [''],
    customConfig: false
  })

  const [customQuota, setCustomQuota] = useState<QuotaConfig>(PLANS[1].quota)

  const selectedPlan = PLANS.find(p => p.id === form.plan) || PLANS[1]

  const validateStep = (currentStep: Step): boolean => {
    switch (currentStep) {
      case 1:
        if (!form.name.trim()) {
          toast({ title: 'Error', description: 'Company name is required', variant: 'destructive' })
          return false
        }
        if (!form.email.trim() || !form.email.includes('@')) {
          toast({ title: 'Error', description: 'Valid email is required', variant: 'destructive' })
          return false
        }
        return true
      case 2:
        const validDomains = form.domains.filter(d => d.trim() && d.includes('.'))
        if (validDomains.length === 0) {
          toast({ title: 'Error', description: 'At least one valid domain is required', variant: 'destructive' })
          return false
        }
        return true
      case 3:
        return true
      case 4:
        return true
      default:
        return true
    }
  }

  const nextStep = () => {
    if (validateStep(step) && step < 4) {
      setStep((step + 1) as Step)
    }
  }

  const prevStep = () => {
    if (step > 1) {
      setStep((step - 1) as Step)
    }
  }

  const handlePlanSelect = (planId: string) => {
    setForm({ ...form, plan: planId })
    const plan = PLANS.find(p => p.id === planId)
    if (plan) {
      setCustomQuota(plan.quota)
    }
  }

  const addDomain = () => {
    const maxDomains = form.customConfig ? customQuota.max_domains : selectedPlan.quota.max_domains
    if (form.domains.length < maxDomains) {
      setForm({ ...form, domains: [...form.domains, ''] })
    } else {
      toast({
        title: 'Limit Reached',
        description: `Maximum ${maxDomains} domains allowed for this plan`,
        variant: 'destructive'
      })
    }
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

  const handleCreate = async () => {
    setLoading(true)

    try {
      const quota = form.customConfig ? customQuota : selectedPlan.quota

      const response = await api.post<CreateResponse>('/admin/tenants', {
        name: form.name,
        description: form.description,
        plan: form.plan,
        domains: form.domains.filter(d => d.trim()),
        quota
      })

      setApiKey(response.api_key)
      setTenantId(response.tenant?.id)
      setCreated(true)
      setStep(5)

      toast({
        title: 'Success',
        description: 'Tenant created successfully'
      })
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to create tenant',
        variant: 'destructive'
      })
    } finally {
      setLoading(false)
    }
  }

  const copyApiKey = () => {
    navigator.clipboard.writeText(apiKey)
    toast({ title: 'Copied!', description: 'API key copied to clipboard' })
  }

  const downloadCredentials = () => {
    const content = `GuardianWAF Tenant Credentials
==============================

Tenant ID: ${tenantId}
Tenant Name: ${form.name}
Plan: ${selectedPlan.name}
Created: ${new Date().toISOString()}

API Key: ${apiKey}

IMPORTANT: Store this API key securely. It will not be shown again.

Configuration:
- Domains: ${form.domains.filter(d => d.trim()).join(', ')}
- Max Requests/Min: ${(form.customConfig ? customQuota : selectedPlan.quota).max_requests_per_minute.toLocaleString()}
- Max Bandwidth: ${(form.customConfig ? customQuota : selectedPlan.quota).max_bandwidth_mbps} Mbps

API Documentation: https://docs.guardianwaf.com/api
Support: support@guardianwaf.com
`
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `guardianwaf-credentials-${tenantId}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  const renderStepIndicator = () => (
    <div className="flex items-center justify-center mb-8">
      <div className="flex items-center gap-2">
        {[1, 2, 3, 4, 5].map((s, i) => (
          <div key={s} className="flex items-center">
            <div
              className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium transition-colors ${
                step >= s
                  ? 'bg-accent text-white'
                  : 'bg-gray-200 dark:bg-gray-700 text-gray-500'
              } ${step === s ? 'ring-2 ring-accent/30' : ''}`}
            >
              {step > s && s !== 5 ? <Check className="w-4 h-4" /> : s}
            </div>
            {i < 4 && (
              <div
                className={`w-12 h-1 mx-2 transition-colors ${
                  step > s ? 'bg-accent' : 'bg-gray-200 dark:bg-gray-700'
                }`}
              />
            )}
          </div>
        ))}
      </div>
    </div>
  )

  const renderStepContent = () => {
    switch (step) {
      case 1:
        return (
          <div className="space-y-6">
            <div className="text-center mb-6">
              <h2 className="text-2xl font-bold">Company Information</h2>
              <p className="text-gray-500">Tell us about your organization</p>
            </div>

            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="name">Company/Organization Name *</Label>
                <div className="relative">
                  <Building2 className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <Input
                    id="name"
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    placeholder="ACME Corporation"
                    className="pl-10"
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="email">Contact Email *</Label>
                <Input
                  id="email"
                  type="email"
                  value={form.email}
                  onChange={(e) => setForm({ ...form, email: e.target.value })}
                  placeholder="admin@acme.com"
                  required
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="description">Description (Optional)</Label>
                <Input
                  id="description"
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  placeholder="Brief description of the tenant"
                />
              </div>
            </div>
          </div>
        )

      case 2:
        return (
          <div className="space-y-6">
            <div className="text-center mb-6">
              <h2 className="text-2xl font-bold">Domain Configuration</h2>
              <p className="text-gray-500">Add domains you want to protect ({form.domains.filter(d => d.trim()).length}/{selectedPlan.quota.max_domains})</p>
            </div>

            <div className="space-y-4">
              {form.domains.map((domain, index) => (
                <div key={index} className="flex items-center gap-2">
                  <div className="relative flex-1">
                    <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                    <Input
                      value={domain}
                      onChange={(e) => updateDomain(index, e.target.value)}
                      placeholder="example.com"
                      className="pl-10"
                    />
                  </div>
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

              <Button
                type="button"
                variant="outline"
                onClick={addDomain}
                disabled={form.domains.length >= selectedPlan.quota.max_domains}
                className="w-full"
              >
                <Globe className="w-4 h-4 mr-2" />
                Add Domain
              </Button>

              <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg text-sm text-blue-800 dark:text-blue-200">
                <strong>Note:</strong> Make sure to configure DNS to point to this WAF instance after onboarding.
              </div>
            </div>
          </div>
        )

      case 3:
        return (
          <div className="space-y-6">
            <div className="text-center mb-6">
              <h2 className="text-2xl font-bold">Select Your Plan</h2>
              <p className="text-gray-500">Choose the plan that fits your needs</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {PLANS.map((plan) => {
                const Icon = plan.icon
                const isSelected = form.plan === plan.id

                return (
                  <Card
                    key={plan.id}
                    className={`cursor-pointer transition-all ${
                      isSelected
                        ? 'border-accent ring-2 ring-accent/20'
                        : 'hover:border-gray-300 dark:hover:border-gray-600'
                    } ${plan.recommended ? 'relative' : ''}`}
                    onClick={() => handlePlanSelect(plan.id)}
                  >
                    {plan.recommended && (
                      <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                        <span className="bg-accent text-white text-xs px-3 py-1 rounded-full font-medium">
                          Recommended
                        </span>
                      </div>
                    )}
                    <CardContent className="p-6">
                      <div className="flex items-start gap-4">
                        <div className={`p-3 rounded-lg ${isSelected ? 'bg-accent/10' : 'bg-gray-100 dark:bg-gray-800'}`}>
                          <Icon className={`w-6 h-6 ${isSelected ? 'text-accent' : 'text-gray-500'}`} />
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center justify-between">
                            <h3 className="font-semibold text-lg">{plan.name}</h3>
                            <div className="text-xl font-bold">{plan.price}<span className="text-sm text-gray-500 font-normal">/mo</span></div>
                          </div>
                          <p className="text-sm text-gray-500 mt-1">{plan.description}</p>
                          <ul className="mt-4 space-y-2">
                            {plan.features.slice(0, 4).map((feature, i) => (
                              <li key={i} className="text-sm flex items-center gap-2">
                                <Check className="w-4 h-4 text-green-500 shrink-0" />
                                {feature}
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )
              })}
            </div>

            <div className="flex items-center gap-2 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
              <input
                type="checkbox"
                id="customConfig"
                checked={form.customConfig}
                onChange={(e) => setForm({ ...form, customConfig: e.target.checked })}
                className="rounded border-gray-300"
              />
              <Label htmlFor="customConfig" className="text-sm cursor-pointer">
                I want to customize resource quotas manually
              </Label>
            </div>

            {form.customConfig && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Custom Quota Configuration</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Max Domains</Label>
                      <Input
                        type="number"
                        value={customQuota.max_domains}
                        onChange={(e) => setCustomQuota({ ...customQuota, max_domains: parseInt(e.target.value) || 1 })}
                        min={1}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Max Rules</Label>
                      <Input
                        type="number"
                        value={customQuota.max_rules}
                        onChange={(e) => setCustomQuota({ ...customQuota, max_rules: parseInt(e.target.value) || 1 })}
                        min={1}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Rate Limit Rules</Label>
                      <Input
                        type="number"
                        value={customQuota.max_rate_limit_rules}
                        onChange={(e) => setCustomQuota({ ...customQuota, max_rate_limit_rules: parseInt(e.target.value) || 1 })}
                        min={1}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Requests/Min</Label>
                      <Input
                        type="number"
                        value={customQuota.max_requests_per_minute}
                        onChange={(e) => setCustomQuota({ ...customQuota, max_requests_per_minute: parseInt(e.target.value) || 100 })}
                        min={100}
                        step={100}
                      />
                    </div>
                    <div className="space-y-2 col-span-2">
                      <Label>Max Bandwidth (Mbps)</Label>
                      <Input
                        type="number"
                        value={customQuota.max_bandwidth_mbps}
                        onChange={(e) => setCustomQuota({ ...customQuota, max_bandwidth_mbps: parseInt(e.target.value) || 10 })}
                        min={10}
                      />
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        )

      case 4:
        return (
          <div className="space-y-6">
            <div className="text-center mb-6">
              <h2 className="text-2xl font-bold">Review & Create</h2>
              <p className="text-gray-500">Verify everything looks good</p>
            </div>

            <div className="space-y-4">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Building2 className="w-4 h-4" />
                    Company Information
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-500">Name</span>
                    <span className="font-medium">{form.name}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Email</span>
                    <span className="font-medium">{form.email}</span>
                  </div>
                  {form.description && (
                    <div className="flex justify-between">
                      <span className="text-gray-500">Description</span>
                      <span className="font-medium">{form.description}</span>
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Globe className="w-4 h-4" />
                    Domains ({form.domains.filter(d => d.trim()).length})
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-2">
                    {form.domains.filter(d => d.trim()).map((domain, i) => (
                      <span key={i} className="px-2 py-1 bg-gray-100 dark:bg-gray-800 rounded text-sm">
                        {domain}
                      </span>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Sparkles className="w-4 h-4" />
                    Plan: {selectedPlan.name}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2 text-sm">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-2 bg-gray-50 dark:bg-gray-800 rounded">
                      <div className="text-gray-500">Max Domains</div>
                      <div className="font-medium">{(form.customConfig ? customQuota : selectedPlan.quota).max_domains}</div>
                    </div>
                    <div className="p-2 bg-gray-50 dark:bg-gray-800 rounded">
                      <div className="text-gray-500">Max Rules</div>
                      <div className="font-medium">{(form.customConfig ? customQuota : selectedPlan.quota).max_rules}</div>
                    </div>
                    <div className="p-2 bg-gray-50 dark:bg-gray-800 rounded">
                      <div className="text-gray-500">Requests/Min</div>
                      <div className="font-medium">{(form.customConfig ? customQuota : selectedPlan.quota).max_requests_per_minute.toLocaleString()}</div>
                    </div>
                    <div className="p-2 bg-gray-50 dark:bg-gray-800 rounded">
                      <div className="text-gray-500">Bandwidth</div>
                      <div className="font-medium">{(form.customConfig ? customQuota : selectedPlan.quota).max_bandwidth_mbps} Mbps</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        )

      case 5:
        return (
          <div className="space-y-6">
            <div className="text-center">
              <div className="w-16 h-16 bg-green-100 dark:bg-green-900/30 rounded-full flex items-center justify-center mx-auto mb-4">
                <Check className="w-8 h-8 text-green-600" />
              </div>
              <h2 className="text-2xl font-bold text-green-600">Tenant Created Successfully!</h2>
              <p className="text-gray-500 mt-2">Your tenant is ready to use</p>
            </div>

            <Card className="border-yellow-200 dark:border-yellow-800 bg-yellow-50/50 dark:bg-yellow-900/10">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2 text-yellow-800 dark:text-yellow-200">
                  <Key className="w-5 h-5" />
                  API Key - Copy Now!
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-yellow-800 dark:text-yellow-200">
                  <strong>Important:</strong> This API key will only be shown once. Copy and store it securely.
                </p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 p-3 bg-black text-green-400 rounded font-mono text-xs break-all">
                    {apiKey}
                  </code>
                  <Button onClick={copyApiKey} variant="secondary">
                    <Copy className="w-4 h-4" />
                  </Button>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-base">Tenant Details</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500">Tenant ID</span>
                  <code className="font-mono bg-gray-100 dark:bg-gray-800 px-2 py-0.5 rounded">{tenantId}</code>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Name</span>
                  <span>{form.name}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Plan</span>
                  <span>{selectedPlan.name}</span>
                </div>
              </CardContent>
            </Card>

            <div className="space-y-3">
              <Button onClick={downloadCredentials} variant="outline" className="w-full">
                <Download className="w-4 h-4 mr-2" />
                Download Credentials
              </Button>

              <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg text-sm">
                <h4 className="font-semibold mb-2">Next Steps:</h4>
                <ol className="list-decimal list-inside space-y-1 ml-2">
                  <li>Save the API key in your password manager</li>
                  <li>Share credentials with your customer securely</li>
                  <li>Configure DNS to point to this WAF instance</li>
                  <li>Customer can start using the API immediately</li>
                </ol>
              </div>
            </div>
          </div>
        )
    }
  }

  return (
    <div className="max-w-3xl mx-auto">
      {/* Header */}
      <div className="flex items-center gap-4 mb-6">
        <Button
          variant="ghost"
          onClick={() => step === 5 ? window.location.href = '/tenants' : window.history.back()}
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          {step === 5 ? 'Back to Tenants' : 'Back'}
        </Button>
        <h1 className="text-2xl font-bold">Create New Tenant</h1>
      </div>

      {/* Step Indicator */}
      {renderStepIndicator()}

      {/* Step Content */}
      <Card>
        <CardContent className="p-6">
          {renderStepContent()}
        </CardContent>
      </Card>

      {/* Navigation Buttons */}
      {step < 5 && (
        <div className="flex justify-between mt-6">
          <Button
            variant="outline"
            onClick={prevStep}
            disabled={step === 1}
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back
          </Button>

          {step < 4 ? (
            <Button onClick={nextStep}>
              Next
              <ArrowRight className="w-4 h-4 ml-2" />
            </Button>
          ) : (
            <Button onClick={handleCreate} disabled={loading}>
              {loading ? 'Creating...' : 'Create Tenant'}
              <Check className="w-4 h-4 ml-2" />
            </Button>
          )}
        </div>
      )}

      {/* Done Button */}
      {step === 5 && (
        <div className="flex justify-center mt-6">
          <Button onClick={() => window.location.href = '/tenants'} size="lg">
            Done
            <Check className="w-4 h-4 ml-2" />
          </Button>
        </div>
      )}
    </div>
  )
}
