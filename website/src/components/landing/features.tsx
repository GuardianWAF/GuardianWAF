import {
  Shield,
  Package,
  Rocket,
  BarChart3,
  Bot,
  Zap,
  Lock,
  Gauge,
  Search,
  Globe,
  Server,
  Puzzle,
  Database,
  Key,
  AlertTriangle,
  Route,
  Brain,
  Container,
  Bell,
  Activity,
  GitBranch,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'

const features = [
  {
    icon: Shield,
    title: 'Multi-Layer Detection',
    description: 'SQL injection, XSS, path traversal, command injection, XXE, SSRF, and bot detection with tokenizer-based scoring engine.',
  },
  {
    icon: Package,
    title: 'Zero Dependencies',
    description: 'Built entirely with Go\'s standard library. No external modules, no supply chain risk, no dependency hell. Single binary.',
  },
  {
    icon: Globe,
    title: 'Multi-Domain Routing',
    description: 'Virtual hosts with domain-based routing, wildcard support (*.example.com), and per-domain TLS certificates via SNI.',
  },
  {
    icon: Server,
    title: 'Load Balancing & Health Checks',
    description: 'Four strategies (round-robin, weighted, least-conn, IP hash), active health checks, and circuit breaker per target.',
  },
  {
    icon: Puzzle,
    title: 'JS Challenge (PoW)',
    description: 'SHA-256 proof-of-work challenge for suspicious requests. Stops bots, passes real browsers. Configurable difficulty.',
  },
  {
    icon: Lock,
    title: 'Auto TLS & ACME',
    description: 'Built-in TLS termination with SNI, certificate hot-reload, ACME/Let\'s Encrypt client, and HTTP-to-HTTPS redirect.',
  },
  {
    icon: Database,
    title: 'Threat Intelligence',
    description: 'IP and domain reputation checking with JSONL/CSV/JSON feeds. LRU cache for fast lookups. CIDR range matching.',
  },
  {
    icon: Route,
    title: 'CORS Security',
    description: 'Origin validation with wildcard patterns, preflight handling, strict mode blocking. Full CORS policy enforcement.',
  },
  {
    icon: Key,
    title: 'API Security',
    description: 'JWT validation (RS256/ES256/HS256), JWKS endpoint support, API key authentication with path-based authorization.',
  },
  {
    icon: AlertTriangle,
    title: 'ATO Protection',
    description: 'Account takeover prevention: brute force detection, credential stuffing detection, password spray, impossible travel.',
  },
  {
    icon: Gauge,
    title: 'Real-Time Dashboard',
    description: 'Live monitoring, event details, upstream health, configuration editor, routing manager, and light/dark theme.',
  },
  {
    icon: Zap,
    title: 'Sub-Millisecond Latency',
    description: 'Optimized pipeline processes requests in under 1ms at p99. Zero-allocation hot path with sync.Pool and atomic counters.',
  },
  {
    icon: Rocket,
    title: 'Three Deploy Modes',
    description: 'Standalone reverse proxy (replaces nginx), embeddable Go library middleware, or lightweight sidecar proxy.',
  },
  {
    icon: BarChart3,
    title: 'Scoring Engine',
    description: 'Intelligent threat scoring with configurable block/log thresholds, per-detector multipliers, and graduated responses.',
  },
  {
    icon: Bot,
    title: 'MCP Integration',
    description: '15 MCP tools over stdio + SSE transports. Remote access via HTTP with API key auth. Claude Desktop, VS Code, and CLI support.',
  },
  {
    icon: Search,
    title: 'Deep Inspection',
    description: 'Custom tokenizer decomposes payloads into semantic tokens. State-machine analysis with gzip/deflate body decompression.',
  },
  {
    icon: Brain,
    title: 'AI Threat Analysis',
    description: 'Background LLM analysis of suspicious events. 400+ AI providers from models.dev. Auto-block IPs with cost control limits.',
  },
  {
    icon: Container,
    title: 'Docker Auto-Discovery',
    description: 'Automatic backend discovery via container labels (gwaf.*). Zero-config service mesh with event-driven hot-reload.',
  },
  {
    icon: Bell,
    title: 'Webhook Alerting',
    description: 'Real-time notifications to Slack, Discord, or custom HTTP endpoints. Per-IP cooldown, event filtering, and min-score thresholds.',
  },
  {
    icon: Activity,
    title: 'Prometheus Metrics',
    description: 'Built-in /metrics endpoint for Grafana integration. Request counters, block rates, latency, and /healthz for K8s probes.',
  },
  {
    icon: GitBranch,
    title: 'Routing Topology',
    description: 'Interactive React Flow graph visualizing the full request path: clients → WAF → vhosts → routes → upstreams → targets.',
  },
]

export function Features() {
  return (
    <section id="features" className="py-20 sm:py-28" aria-labelledby="features-heading">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12 sm:mb-16">
          <h2 id="features-heading" className="text-3xl sm:text-4xl font-bold text-foreground">
            Everything you need. Nothing you don't.
          </h2>
          <p className="mt-4 text-lg text-muted max-w-2xl mx-auto">
            A complete WAF solution built from the ground up in Go, designed for modern cloud-native applications.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
          {features.map((feature) => {
            const Icon = feature.icon
            return (
              <Card
                key={feature.title}
                className="group hover:border-accent/50 transition-all duration-300 hover:shadow-lg hover:shadow-accent/5"
              >
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-accent/10 text-accent group-hover:bg-accent/20 transition-colors duration-300">
                      <Icon className="h-5 w-5" />
                    </div>
                    <CardTitle>{feature.title}</CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-sm leading-relaxed">
                    {feature.description}
                  </CardDescription>
                </CardContent>
              </Card>
            )
          })}
        </div>
      </div>
    </section>
  )
}
