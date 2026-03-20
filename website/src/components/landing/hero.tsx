import { ArrowRight, Github, Shield } from 'lucide-react'
import { Button } from '@/components/ui/button'

const stats = [
  { value: '0', label: 'Dependencies' },
  { value: '<1ms', label: 'p99 Latency' },
  { value: '13', label: 'Security Layers' },
  { value: '400+', label: 'AI Providers' },
  { value: '15', label: 'MCP Tools' },
]

export function Hero() {
  return (
    <section className="relative overflow-hidden" aria-labelledby="hero-heading">
      {/* Background gradient */}
      <div className="absolute inset-0 bg-gradient-to-b from-accent/5 via-transparent to-transparent pointer-events-none" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_50%_at_50%_-20%,rgba(59,130,246,0.12),transparent)] pointer-events-none" />

      <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 pt-20 pb-16 sm:pt-32 sm:pb-24">
        <div className="text-center">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 rounded-full border border-border bg-card px-4 py-1.5 text-sm text-muted mb-8">
            <Shield className="h-4 w-4 text-accent" />
            <span>Production-ready WAF — protect any backend, any language</span>
          </div>

          {/* Heading */}
          <h1
            id="hero-heading"
            className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight text-foreground"
          >
            <span className="block">Zero-dependency WAF.</span>
            <span className="block mt-2 bg-gradient-to-r from-accent via-blue-400 to-cyan-400 bg-clip-text text-transparent">
              One binary. Total protection.
            </span>
          </h1>

          {/* Description */}
          <p className="mx-auto mt-6 max-w-2xl text-lg sm:text-xl text-muted leading-relaxed">
            Production-grade WAF, reverse proxy, and service gateway in pure Go.
            AI threat analysis, Docker auto-discovery, webhook alerting, Prometheus metrics,
            and interactive dashboard. Zero dependencies. Single binary.
          </p>

          {/* CTA Buttons */}
          <div className="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4">
            <a href="https://github.com/GuardianWAF/GuardianWAF/releases" target="_blank" rel="noopener noreferrer">
              <Button size="lg" className="gap-2 text-base">
                Download
                <ArrowRight className="h-4 w-4" />
              </Button>
            </a>
            <a href="https://github.com/GuardianWAF/GuardianWAF" target="_blank" rel="noopener noreferrer">
              <Button variant="secondary" size="lg" className="gap-2 text-base">
                <Github className="h-5 w-5" />
                View on GitHub
              </Button>
            </a>
          </div>

          {/* Stats Bar */}
          <div className="mt-16 mx-auto max-w-3xl" role="list" aria-label="Key statistics">
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 sm:gap-0 sm:divide-x divide-border rounded-xl border border-border bg-card/50 backdrop-blur-sm p-4 sm:p-0">
              {stats.map((stat) => (
                <div
                  key={stat.label}
                  className="flex flex-col items-center gap-1 sm:py-4"
                  role="listitem"
                >
                  <span className="text-2xl sm:text-3xl font-bold text-foreground">
                    {stat.value}
                  </span>
                  <span className="text-xs sm:text-sm text-muted">{stat.label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
