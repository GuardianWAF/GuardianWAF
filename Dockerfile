# GuardianWAF Dockerfile - Multi-arch build for GHCR
# Build with: docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/guardianwaf/guardianwaf:latest .

# Stage 1: Build React dashboard
FROM --platform=$BUILDPLATFORM node:22.14.0-alpine AS ui-builder

WORKDIR /ui
COPY internal/dashboard/ui/package.json internal/dashboard/ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY internal/dashboard/ui/ .
RUN npm run build

# Stage 2: Build Go binary
FROM --platform=$BUILDPLATFORM golang:1.25.0-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

WORKDIR /app

# Install CA certificates for HTTPS downloads
RUN apk add --no-cache ca-certificates curl

COPY go.mod ./
RUN go mod download

COPY . .

# Copy React build output into Go embed location
COPY --from=ui-builder /ui/dist internal/dashboard/dist/

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o guardianwaf ./cmd/guardianwaf

# Stage 3: Runtime
FROM alpine:3.21.3

# Labels for GHCR
LABEL org.opencontainers.image.title="GuardianWAF" \
      org.opencontainers.image.description="Zero-dependency Web Application Firewall written in Go" \
      org.opencontainers.image.source="https://github.com/guardianwaf/guardianwaf" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image vendors="GuardianWAF" \
      org.opencontainers.image.version="1.1.0"

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -H -s /sbin/nologin guardianwaf && \
    mkdir -p /var/lib/guardianwaf/ai /etc/guardianwaf && \
    chown -R guardianwaf:guardianwaf /var/lib/guardianwaf

# Copy binary from builder
COPY --from=builder /app/guardianwaf /usr/local/bin/guardianwaf

WORKDIR /var/lib/guardianwaf
USER guardianwaf

EXPOSE 8088 8443 9443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/guardianwaf", "healthcheck"]

ENTRYPOINT ["guardianwaf"]
CMD ["serve"]
