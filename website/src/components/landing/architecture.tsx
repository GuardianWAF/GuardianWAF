import { useState } from 'react'
import { cn } from '@/lib/utils'

const steps = [
  {
    id: 'ipacl',
    label: 'IP ACL',
    shortLabel: 'IP',
    description: 'IP allowlist/blocklist with CIDR matching. Auto-ban for repeated violations. Radix tree for sub-microsecond lookups.',
    color: 'text-slate-400',
    bgColor: 'bg-slate-400/10',
    borderColor: 'border-slate-400/30',
    activeColor: 'bg-slate-400/20 border-slate-400/60',
  },
  {
    id: 'threatintel',
    label: 'Threat Intel',
    shortLabel: 'TI',
    description: 'IP and domain reputation checking against threat feeds. LRU cache for fast lookups. JSONL/CSV/JSON feed support.',
    color: 'text-rose-400',
    bgColor: 'bg-rose-400/10',
    borderColor: 'border-rose-400/30',
    activeColor: 'bg-rose-400/20 border-rose-400/60',
  },
  {
    id: 'cors',
    label: 'CORS',
    shortLabel: 'CO',
    description: 'Cross-Origin Resource Sharing validation with wildcard patterns. Origin allowlist, preflight handling, strict mode.',
    color: 'text-cyan-400',
    bgColor: 'bg-cyan-400/10',
    borderColor: 'border-cyan-400/30',
    activeColor: 'bg-cyan-400/20 border-cyan-400/60',
  },
  {
    id: 'ratelimit',
    label: 'Rate Limit',
    shortLabel: 'RL',
    description: 'Token bucket rate limiting per IP or IP+path. Configurable windows, burst allowances, auto-ban triggers.',
    color: 'text-indigo-400',
    bgColor: 'bg-indigo-400/10',
    borderColor: 'border-indigo-400/30',
    activeColor: 'bg-indigo-400/20 border-indigo-400/60',
  },
  {
    id: 'ato',
    label: 'ATO Protection',
    shortLabel: 'AT',
    description: 'Account takeover prevention: brute force detection, credential stuffing, password spray, impossible travel.',
    color: 'text-pink-400',
    bgColor: 'bg-pink-400/10',
    borderColor: 'border-pink-400/30',
    activeColor: 'bg-pink-400/20 border-pink-400/60',
  },
  {
    id: 'apisecurity',
    label: 'API Security',
    shortLabel: 'AP',
    description: 'JWT validation (RS256/ES256/HS256), JWKS endpoint support, API key authentication with path-based authorization.',
    color: 'text-teal-400',
    bgColor: 'bg-teal-400/10',
    borderColor: 'border-teal-400/30',
    activeColor: 'bg-teal-400/20 border-teal-400/60',
  },
  {
    id: 'sanitizer',
    label: 'Sanitizer',
    shortLabel: 'SA',
    description: 'Request normalization and validation: URL/header/body size limits, null byte blocking, encoding normalization.',
    color: 'text-amber-400',
    bgColor: 'bg-amber-400/10',
    borderColor: 'border-amber-400/30',
    activeColor: 'bg-amber-400/20 border-amber-400/60',
  },
  {
    id: 'detection',
    label: 'Detection',
    shortLabel: 'DT',
    description: 'Six tokenizer-based detectors: SQLi, XSS, Path Traversal, Command Injection, XXE, SSRF. State-machine analysis.',
    color: 'text-orange-400',
    bgColor: 'bg-orange-400/10',
    borderColor: 'border-orange-400/30',
    activeColor: 'bg-orange-400/20 border-orange-400/60',
  },
  {
    id: 'botdetect',
    label: 'Bot Detection',
    shortLabel: 'BD',
    description: 'JA3/JA4 TLS fingerprinting, User-Agent analysis, behavioral analysis. JS Challenge (SHA-256 PoW) for suspicious clients.',
    color: 'text-purple-400',
    bgColor: 'bg-purple-400/10',
    borderColor: 'border-purple-400/30',
    activeColor: 'bg-purple-400/20 border-purple-400/60',
  },
  {
    id: 'response',
    label: 'Response',
    shortLabel: 'RS',
    description: 'Security headers injection (HSTS, X-Frame-Options, CSP), data masking (credit cards, SSN, API keys), error pages.',
    color: 'text-green-400',
    bgColor: 'bg-green-400/10',
    borderColor: 'border-green-400/30',
    activeColor: 'bg-green-400/20 border-green-400/60',
  },
]

export function Architecture() {
  const [activeStep, setActiveStep] = useState<string | null>(null)

  return (
    <section id="architecture" className="py-20 sm:py-28 bg-card/30" aria-labelledby="architecture-heading">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12 sm:mb-16">
          <h2 id="architecture-heading" className="text-3xl sm:text-4xl font-bold text-foreground">
            10-Layer Security Pipeline
          </h2>
          <p className="mt-4 text-lg text-muted max-w-2xl mx-auto">
            Every request flows through ten modular layers, each designed for sub-millisecond processing. Zero external dependencies.
          </p>
        </div>

        {/* Pipeline visualization */}
        <div className="relative">
          {/* Desktop: two-row horizontal pipeline */}
          <div className="hidden lg:flex flex-col items-center gap-6">
            {/* First row: layers 1-5 */}
            <div className="flex items-center justify-center gap-2">
              {steps.slice(0, 5).map((step, i) => (
                <div key={step.id} className="flex items-center">
                  <button
                    className={cn(
                      'relative flex flex-col items-center gap-2 px-4 py-3 rounded-xl border-2 transition-all duration-300 cursor-pointer min-w-[110px]',
                      activeStep === step.id
                        ? step.activeColor
                        : `${step.bgColor} ${step.borderColor} hover:scale-105`
                    )}
                    onMouseEnter={() => setActiveStep(step.id)}
                    onMouseLeave={() => setActiveStep(null)}
                    onFocus={() => setActiveStep(step.id)}
                    onBlur={() => setActiveStep(null)}
                    aria-label={`Pipeline step: ${step.label}`}
                  >
                    <span className={cn('text-xs font-mono font-bold', step.color)}>
                      {String(i + 1).padStart(2, '0')}
                    </span>
                    <span className="text-xs font-semibold text-foreground">{step.label}</span>
                  </button>
                  {i < 4 && (
                    <div className="flex items-center px-1">
                      <div className="w-4 h-px bg-border" />
                      <div className="w-0 h-0 border-t-[4px] border-t-transparent border-b-[4px] border-b-transparent border-l-[5px] border-l-border" />
                    </div>
                  )}
                </div>
              ))}
            </div>
            {/* Arrow down */}
            <div className="flex items-center">
              <div className="h-6 w-px bg-border" />
              <div className="w-0 h-0 border-l-[5px] border-l-transparent border-r-[5px] border-r-transparent border-t-[6px] border-t-border ml-[-5px]" />
            </div>
            {/* Second row: layers 6-10 */}
            <div className="flex items-center justify-center gap-2">
              {steps.slice(5).map((step, i) => (
                <div key={step.id} className="flex items-center">
                  <button
                    className={cn(
                      'relative flex flex-col items-center gap-2 px-4 py-3 rounded-xl border-2 transition-all duration-300 cursor-pointer min-w-[110px]',
                      activeStep === step.id
                        ? step.activeColor
                        : `${step.bgColor} ${step.borderColor} hover:scale-105`
                    )}
                    onMouseEnter={() => setActiveStep(step.id)}
                    onMouseLeave={() => setActiveStep(null)}
                    onFocus={() => setActiveStep(step.id)}
                    onBlur={() => setActiveStep(null)}
                    aria-label={`Pipeline step: ${step.label}`}
                  >
                    <span className={cn('text-xs font-mono font-bold', step.color)}>
                      {String(i + 6).padStart(2, '0')}
                    </span>
                    <span className="text-xs font-semibold text-foreground">{step.label}</span>
                  </button>
                  {i < 4 && (
                    <div className="flex items-center px-1">
                      <div className="w-4 h-px bg-border" />
                      <div className="w-0 h-0 border-t-[4px] border-t-transparent border-b-[4px] border-b-transparent border-l-[5px] border-l-border" />
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Mobile: vertical pipeline */}
          <div className="lg:hidden flex flex-col items-center gap-2">
            {steps.map((step, i) => (
              <div key={step.id} className="flex flex-col items-center w-full max-w-sm">
                <button
                  className={cn(
                    'w-full flex items-center gap-4 px-5 py-4 rounded-xl border-2 transition-all duration-300 cursor-pointer',
                    activeStep === step.id
                      ? step.activeColor
                      : `${step.bgColor} ${step.borderColor}`
                  )}
                  onClick={() => setActiveStep(activeStep === step.id ? null : step.id)}
                  aria-label={`Pipeline step: ${step.label}`}
                  aria-expanded={activeStep === step.id}
                >
                  <span className={cn('text-xs font-mono font-bold shrink-0', step.color)}>
                    {String(i + 1).padStart(2, '0')}
                  </span>
                  <span className="text-sm font-semibold text-foreground">{step.label}</span>
                </button>
                {activeStep === step.id && (
                  <div className="w-full max-w-sm mt-2 px-4 py-3 rounded-lg bg-card border border-border text-sm text-muted leading-relaxed">
                    {step.description}
                  </div>
                )}
                {i < steps.length - 1 && (
                  <div className="flex flex-col items-center py-1">
                    <div className="h-4 w-px bg-border" />
                    <div className="w-0 h-0 border-l-[5px] border-l-transparent border-r-[5px] border-r-transparent border-t-[6px] border-t-border" />
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Description panel (desktop) */}
          <div className="hidden lg:block mt-8 text-center min-h-[80px]">
            {activeStep ? (
              <div className="mx-auto max-w-xl animate-in fade-in duration-200">
                <p className="text-muted leading-relaxed">
                  {steps.find((s) => s.id === activeStep)?.description}
                </p>
              </div>
            ) : (
              <p className="text-muted/60 text-sm">
                Hover over a layer to learn more
              </p>
            )}
          </div>
        </div>
      </div>
    </section>
  )
}
