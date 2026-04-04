# GuardianWAF Architecture

This document describes the GuardianWAF architecture using Mermaid diagrams.

## System Overview

```mermaid
flowchart TB
    subgraph Client["Client Layer"]
        Browser["Browser/User Agent"]
        Bot["Bot/Attacker"]
    end

    subgraph Edge["Edge Layer"]
        DNS["DNS"]
        CDN["CDN (optional)"]
    end

    subgraph WAF["GuardianWAF"]
        subgraph Ingress["Ingress"]
            HTTP[":8080 HTTP"]
            HTTPS[":8443 HTTPS"]
            Dash[":9443 Dashboard"]
        end

        subgraph Pipeline["13-Layer Pipeline"]
            direction TB
            L1["100: IP ACL<br/>Radix Tree CIDR"]
            L2["125: Threat Intel<br/>Reputation Feeds"]
            L3["150: CORS<br/>Origin Validation"]
            L4["150: Custom Rules<br/>Geo-aware"]
            L5["200: Rate Limit<br/>Token Bucket"]
            L6["250: ATO Protection<br/>Brute Force"]
            L7["275: API Security<br/>JWT/API Key"]
            L8["300: Sanitizer<br/>Normalization"]
            L9["400: Detection<br/>6 Detectors"]
            L10["500: Bot Detection<br/>JA3/JA4"]
            L11["600: Response<br/>Headers/Masking"]

            L1 --> L2 --> L3 --> L4 --> L5 --> L6 --> L7 --> L8 --> L9 --> L10 --> L11
        end

        subgraph Challenge["Challenge Layer"]
            JS["JS Challenge<br/>Score 40-79"]
        end

        subgraph Proxy["Proxy Layer"]
            LB["Load Balancer<br/>RR/Weighted/Least-Conn"]
            HC["Health Checks"]
            CB["Circuit Breaker"]
            WS["WebSocket"]
        end

        subgraph Services["Internal Services"]
            AI["AI Analysis<br/>Background Batch"]
            Alert["Alerting<br/>Email/Webhooks"]
            EventStore["Event Store<br/>Ring Buffer"]
            GeoIP["GeoIP DB"]
        end

        subgraph Management["Management"]
            Dashboard["React Dashboard<br/>SSE Real-time"]
            MCP["MCP Server<br/>21 Tools"]
            API["REST API"]
            Metrics["/metrics<br/>Prometheus"]
        end
    end

    subgraph Backend["Backend Layer"]
        App1["App Server 1"]
        App2["App Server 2"]
        App3["App Server 3"]
    end

    subgraph Docker["Docker Integration"]
        Discovery["Auto-Discovery<br/>Label-based"]
        Events["Event Watcher"]
    end

    Client --> Edge
    Edge --> Ingress

    HTTP --> Pipeline
    HTTPS --> Pipeline
    Pipeline --> Challenge
    Challenge --> Proxy
    Proxy --> Backend

    L9 -.->|High Score| Block["Block Page"]
    L10 -.->|Suspicious| Challenge

    Pipeline -.->|Events| EventStore
    EventStore -.->|Batch| AI
    Pipeline -.->|Geo Data| GeoIP
    Pipeline -.->|Triggers| Alert

    Dashboard --> API
    API --> Pipeline
    MCP --> API
    Metrics --> Pipeline

    Docker -.-> Discovery
    Discovery -.->|Updates| Proxy
```

## Request Flow

```mermaid
sequenceDiagram
    actor Client
    participant WAF as GuardianWAF
    participant Pipeline as 13-Layer Pipeline
    participant Challenge as JS Challenge
    participant Proxy as Reverse Proxy
    participant Backend as Backend Server

    Client->>WAF: HTTP Request
    
    WAF->>Pipeline: Process Request
    
    alt Score >= 80 (Block)
        Pipeline-->>WAF: Block
        WAF-->>Client: 403 Block Page
    else Score 40-79 (Challenge)
        Pipeline-->>WAF: Challenge Required
        WAF->>Challenge: Generate Challenge
        Challenge-->>Client: JS Challenge Page
        Client->>Challenge: Submit Solution
        Challenge-->>WAF: Valid
        WAF->>Proxy: Forward Request
    else Score < 40 (Pass)
        Pipeline-->>WAF: Pass
        WAF->>Proxy: Forward Request
    end
    
    Proxy->>Backend: Proxied Request
    Backend-->>Proxy: Response
    Proxy-->>WAF: Response
    
    opt Response Processing
        WAF->>Pipeline: Process Response
        Pipeline-->>WAF: Masked/Modified Response
    end
    
    WAF-->>Client: Final Response
```

## Component Architecture

```mermaid
flowchart TB
    subgraph Engine["Engine Layer"]
        Pipeline["Pipeline Engine"]
        Scoring["Scoring System"]
        Context["Request Context"]
    end

    subgraph Layers["WAF Layers"]
        subgraph Network["Network"]
            IPACL["IP ACL"]
            RateLimit["Rate Limiting"]
            ThreatIntel["Threat Intel"]
        end

        subgraph Security["Security"]
            CORS["CORS"]
            Rules["Custom Rules"]
            APISecurity["API Security<br/>JWT/API Key"]
            ATO["ATO Protection"]
        end

        subgraph Detection["Detection"]
            Sanitizer["Sanitizer"]
            SQLi["SQLi"]
            XSS["XSS"]
            LFI["LFI"]
            CMDi["CMDi"]
            SSRF["SSRF"]
            XXE["XXE"]
            BotDetect["Bot Detection"]
        end

        subgraph Response["Response"]
            ResponseLayer["Response Layer"]
            Masking["Data Masking"]
            Headers["Security Headers"]
        end
    end

    subgraph Proxy["Proxy Layer"]
        Router["Router"]
        LoadBalancer["Load Balancer"]
        HealthCheck["Health Checks"]
        CircuitBreaker["Circuit Breaker"]
    end

    subgraph Storage["Storage"]
        EventRing["Event Ring Buffer"]
        Config["Config Store"]
        GeoIPDB["GeoIP Database"]
        CertStore["Certificate Store"]
    end

    subgraph External["External Services"]
        SMTP["SMTP Server"]
        Webhook["Webhook Endpoints"]
        ACME["ACME/Let's Encrypt"]
        AIProvider["AI Providers"]
    end

    Engine --> Layers
    Layers --> Proxy
    Engine --> Storage
    Engine -.->|Alerting| External
```

## Data Flow

```mermaid
flowchart LR
    subgraph Input["Input"]
        HTTP["HTTP Request"]
        Config["Configuration"]
        Docker["Docker Events"]
    end

    subgraph Processing["Processing"]
        Parse["Parse Request"]
        Score["Score Calculation"]
        Decide["Decision Engine"]
    end

    subgraph Output["Output"]
        Block["Block"]
        Challenge["JS Challenge"]
        Forward["Forward to Backend"]
        Alert["Send Alert"]
        Log["Log Event"]
    end

    subgraph Storage["Storage"]
        Events["Event Store"]
        Metrics["Metrics"]
    end

    HTTP --> Parse
    Config --> Parse
    Docker --> Parse

    Parse --> Score
    Score --> Decide

    Decide -->|Score >= 80| Block
    Decide -->|40-79| Challenge
    Decide -->|< 40| Forward

    Decide -->|Trigger| Alert
    Decide -->|Always| Log

    Log --> Events
    Log --> Metrics
    Alert -->|Async| SMTP
    Alert -->|Async| Webhook
```

## Deployment Architecture

```mermaid
flowchart TB
    subgraph Internet["Internet"]
        Users["Users/Bots"]
    end

    subgraph Edge["Edge Layer"]
        DNS["DNS/Route53"]
        CDN["CloudFlare/CloudFront"]
    end

    subgraph K8s["Kubernetes Cluster"]
        subgraph Ingress["Ingress Controller"]
            LB["Load Balancer"]
        end

        subgraph WAF_Pods["GuardianWAF Pods"]
            WAF1["WAF Pod 1"]
            WAF2["WAF Pod 2"]
            WAF3["WAF Pod 3"]
        end

        subgraph Backend_Svc["Backend Services"]
            App1["App Pod 1"]
            App2["App Pod 2"]
        end

        subgraph Storage["Storage"]
            PVC["Persistent Volume<br/>Events/Certs"]
        end

        subgraph Monitoring["Monitoring"]
            Prometheus["Prometheus"]
            Grafana["Grafana"]
        end
    end

    subgraph External["External Services"]
        ACME["Let's Encrypt"]
        SMTP["SMTP"]
        Webhooks["Slack/PagerDuty"]
    end

    Users --> DNS
    DNS --> CDN
    CDN --> LB
    LB --> WAF_Pods
    WAF_Pods --> Backend_Svc
    WAF_Pods --> PVC
    WAF_Pods -.->|Metrics| Prometheus
    Prometheus --> Grafana
    WAF_Pods -.->|ACME| ACME
    WAF_Pods -.->|Alerts| SMTP
    WAF_Pods -.->|Alerts| Webhooks
```

## MCP Integration

```mermaid
flowchart TB
    subgraph AI_Tools["AI Tools"]
        Claude["Claude Code"]
        ClaudeDesktop["Claude Desktop"]
        VSCode["VS Code Extension"]
    end

    subgraph Transport["Transport Layer"]
        STDIO["stdio"]
        SSE["SSE (HTTP)"]
    end

    subgraph MCP_Server["GuardianWAF MCP Server"]
        subgraph Tools["21 Tools"]
            T1["get_stats"]
            T2["get_events"]
            T3["add_blacklist"]
            T4["remove_blacklist"]
            T5["add_whitelist"]
            T6["remove_whitelist"]
            T7["add_ratelimit"]
            T8["remove_ratelimit"]
            T9["add_exclusion"]
            T10["remove_exclusion"]
            T11["set_mode"]
            T12["test_request"]
            T13["get_detectors"]
            T14["get_config"]
            T15["get_alerting_status"]
            T16["add_webhook"]
            T17["remove_webhook"]
            T18["add_email_target"]
            T19["remove_email_target"]
            T20["test_alert"]
            T21["get_top_ips"]
        end

        Handlers["Tool Handlers"]
    end

    subgraph WAF_API["GuardianWAF API"]
        REST["REST Endpoints"]
        Engine["Engine Control"]
    end

    AI_Tools --> Transport
    Transport --> MCP_Server
    Tools --> Handlers
    Handlers --> REST
    REST --> Engine
```

## Directory Structure

```mermaid
flowchart TB
    subgraph Root["GuardianWAF Root"]
        CMD["cmd/guardianwaf/<br/>CLI Entry Points"]
        Internal["internal/<br/>Core Implementation"]
        Docs["docs/<br/>Documentation"]
        Tests["tests/<br/>E2E & Integration"]
        Config["config files"]
    end

    subgraph Internal_Pkgs["Internal Packages"]
        Engine["engine/<br/>Pipeline & Scoring"]
        ConfigPkg["config/<br/>YAML Parser"]
        Layers["layers/<br/>13 WAF Layers"]
        Proxy["proxy/<br/>Reverse Proxy"]
        Dashboard["dashboard/<br/>React UI"]
        MCP["mcp/<br/>AI Integration"]
        AI_Pkg["ai/<br/>Threat Analysis"]
        Events["events/<br/>Event Storage"]
        Docker["docker/<br/>Auto-Discovery"]
        TLS["tls/<br/>Certificate Store"]
        ACME["acme/<br/>Let's Encrypt"]
        GeoIP["geoip/<br/>Geo Database"]
        Alerting["alerting/<br/>Notifications"]
    end

    Internal --> Internal_Pkgs

    subgraph Detection["Detection Layers"]
        SQLi["sqli/<br/>SQL Injection"]
        XSS["xss/<br/>Cross-Site Scripting"]
        LFI["lfi/<br/>Path Traversal"]
        CMDi["cmdi/<br/>Command Injection"]
        SSRF["ssrf/<br/>Server-Side Request Forgery"]
        XXE["xxe/<br/>XML External Entity"]
    end

    subgraph Security["Security Layers"]
        IPACL["ipacl/<br/>IP Access Control"]
        RateLimit["ratelimit/<br/>Rate Limiting"]
        BotDetect["botdetect/<br/>Bot Detection"]
        Challenge["challenge/<br/>JS Challenge"]
        Response["response/<br/>Response Security"]
    end

    Layers --> Detection
    Layers --> Security
```

---

*For implementation details, see [SPECIFICATION.md](design/SPECIFICATION.md)*
