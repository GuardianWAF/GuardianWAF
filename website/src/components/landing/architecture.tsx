import { useState } from 'react'
import { cn } from '@/lib/utils'

const steps = [
  {
    id: 'ingress',
    label: 'Ingress',
    shortLabel: 'IN',
    description: 'Incoming HTTP request enters the WAF pipeline. Connection metadata, headers, and body are captured for analysis.',
    color: 'text-blue-400',
    bgColor: 'bg-blue-400/10',
    borderColor: 'border-blue-400/30',
    activeColor: 'bg-blue-400/20 border-blue-400/60',
  },
  {
    id: 'tokenizer',
    label: 'Tokenizer',
    shortLabel: 'TK',
    description: 'Custom tokenizer breaks URI, headers, and body into semantic tokens. Context-aware parsing identifies payload boundaries.',
    color: 'text-purple-400',
    bgColor: 'bg-purple-400/10',
    borderColor: 'border-purple-400/30',
    activeColor: 'bg-purple-400/20 border-purple-400/60',
  },
  {
    id: 'detectors',
    label: 'Detectors',
    shortLabel: 'DT',
    description: 'Six parallel detectors analyze tokens: SQLi, XSS, Path Traversal, Command Injection, XXE, SSRF. Plus JA3/UA/behavioral bot detection.',
    color: 'text-orange-400',
    bgColor: 'bg-orange-400/10',
    borderColor: 'border-orange-400/30',
    activeColor: 'bg-orange-400/20 border-orange-400/60',
  },
  {
    id: 'scoring',
    label: 'Scoring',
    shortLabel: 'SC',
    description: 'Scoring engine aggregates detector signals with per-rule weights. Composite score determines threat level.',
    color: 'text-yellow-400',
    bgColor: 'bg-yellow-400/10',
    borderColor: 'border-yellow-400/30',
    activeColor: 'bg-yellow-400/20 border-yellow-400/60',
  },
  {
    id: 'decision',
    label: 'Decision',
    shortLabel: 'DC',
    description: 'Action engine applies configurable thresholds. Routes to ALLOW, LOG, JS CHALLENGE (PoW), or BLOCK based on final score.',
    color: 'text-red-400',
    bgColor: 'bg-red-400/10',
    borderColor: 'border-red-400/30',
    activeColor: 'bg-red-400/20 border-red-400/60',
  },
  {
    id: 'response',
    label: 'Response',
    shortLabel: 'RS',
    description: 'Clean requests are load-balanced to upstream targets (4 strategies, health checks, circuit breaker). Blocked requests get branded HTML error pages.',
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
            Detection Pipeline
          </h2>
          <p className="mt-4 text-lg text-muted max-w-2xl mx-auto">
            Every request flows through a six-stage pipeline. Each stage is modular, configurable, and designed for sub-millisecond processing.
          </p>
        </div>

        {/* Pipeline visualization */}
        <div className="relative">
          {/* Desktop: horizontal pipeline */}
          <div className="hidden lg:flex items-center justify-center gap-2">
            {steps.map((step, i) => (
              <div key={step.id} className="flex items-center">
                <button
                  className={cn(
                    'relative flex flex-col items-center gap-2 px-6 py-4 rounded-xl border-2 transition-all duration-300 cursor-pointer min-w-[130px]',
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
                  <span className="text-sm font-semibold text-foreground">{step.label}</span>
                </button>
                {i < steps.length - 1 && (
                  <div className="flex items-center px-1">
                    <div className="w-6 h-px bg-border" />
                    <div className="w-0 h-0 border-t-[5px] border-t-transparent border-b-[5px] border-b-transparent border-l-[6px] border-l-border" />
                  </div>
                )}
              </div>
            ))}
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
                Hover over a stage to learn more
              </p>
            )}
          </div>
        </div>
      </div>
    </section>
  )
}
