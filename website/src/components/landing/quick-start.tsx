import { Tabs } from '@/components/ui/tabs'
import { CodeBlock } from '@/components/ui/code-block'

const standaloneCode = `# Download the latest release
curl -sL https://github.com/GuardianWAF/GuardianWAF/releases/latest/download/guardianwaf_1.1.0_linux_amd64.tar.gz | tar -xz
chmod +x guardianwaf

# Run with default config
./guardianwaf serve --listen :8088 --upstream http://localhost:3000

# Or with a config file
./guardianwaf serve --config guardianwaf.yaml

# Update
curl -sSL https://raw.githubusercontent.com/guardianwaf/guardianwaf/main/scripts/update.sh | bash`

const libraryCode = `package main

import (
    "net/http"
    "github.com/guardianwaf/guardianwaf"
)

func main() {
    // Create a new WAF instance
    waf, err := guardianwaf.New(guardianwaf.Config{
        Mode:       guardianwaf.ModeLibrary,
        BlockScore: 80,
    })
    if err != nil {
        panic(err)
    }

    // Wrap your handler
    mux := http.NewServeMux()
    mux.HandleFunc("/", handler)

    http.ListenAndServe(":8088", waf.Handler(mux))
}`

const sidecarCode = `# docker-compose.yaml
version: "3.8"
services:
  guardianwaf:
    image: ghcr.io/guardianwaf/guardianwaf:latest
    ports:
      - "8088:8088"
    environment:
      - GUARDIANWAF_UPSTREAM=http://app:3000
      - GUARDIANWAF_BLOCK_SCORE=80
    depends_on:
      - app

  app:
    image: your-app:latest
    expose:
      - "3000"`

const dryRunCode = `# Enable dry-run mode to monitor without blocking
./guardianwaf serve \\
  --listen :8088 \\
  --upstream http://localhost:3000 \\
  --dry-run \\
  --dashboard :9090

# All requests pass through, but threats are:
#   - Logged with full detail
#   - Visible in the dashboard at :9090
#   - Scored but not blocked
#
# Perfect for tuning before going live.`

const dockerDiscoveryCode = `# docker-compose.yml — zero-config auto-discovery
services:
  guardianwaf:
    image: guardianwaf/guardianwaf:latest
    ports:
      - "80:8088"
      - "9443:9443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro

  # Just add labels — GuardianWAF discovers automatically
  api:
    image: my-api:latest
    labels:
      gwaf.enable: "true"
      gwaf.host: "api.example.com"
      gwaf.upstream: "api-pool"
      gwaf.health.path: "/healthz"

  web:
    image: nginx:alpine
    labels:
      gwaf.enable: "true"
      gwaf.host: "www.example.com"

# Scale instantly:
# docker compose up -d --scale api=5`

const tabs = [
  {
    id: 'standalone',
    label: 'Standalone',
    content: <CodeBlock code={standaloneCode} language="bash" filename="Terminal" />,
  },
  {
    id: 'docker',
    label: 'Docker Discovery',
    content: <CodeBlock code={dockerDiscoveryCode} language="yaml" filename="docker-compose.yml" />,
  },
  {
    id: 'library',
    label: 'Library',
    content: <CodeBlock code={libraryCode} language="go" filename="main.go" />,
  },
  {
    id: 'sidecar',
    label: 'Sidecar',
    content: <CodeBlock code={sidecarCode} language="yaml" filename="docker-compose.yaml" />,
  },
  {
    id: 'dry-run',
    label: 'Dry-Run',
    content: <CodeBlock code={dryRunCode} language="bash" filename="Terminal" />,
  },
]

export function QuickStart() {
  return (
    <section id="quick-start" className="py-20 sm:py-28 bg-card/30" aria-labelledby="quickstart-heading">
      <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-12 sm:mb-16">
          <h2 id="quickstart-heading" className="text-3xl sm:text-4xl font-bold text-foreground">
            Up and running in minutes
          </h2>
          <p className="mt-4 text-lg text-muted max-w-2xl mx-auto">
            Choose your deployment mode and start protecting your application. No complex setup, no configuration headaches.
          </p>
        </div>

        <Tabs tabs={tabs} defaultTab="standalone" />
      </div>
    </section>
  )
}
