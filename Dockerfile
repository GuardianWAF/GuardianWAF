# Stage 1: Build React dashboard
FROM --platform=$BUILDPLATFORM node:22-alpine AS ui-builder

WORKDIR /ui
COPY internal/dashboard/ui/package.json internal/dashboard/ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY internal/dashboard/ui/ .
RUN npm run build

# Stage 2: Build Go binary
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .

# Copy React build output into Go embed location
COPY --from=ui-builder /ui/dist internal/dashboard/dist/

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o guardianwaf ./cmd/guardianwaf

# Stage 3: Runtime
FROM alpine:3.20

LABEL org.opencontainers.image.title="GuardianWAF" \
      org.opencontainers.image.description="Zero-dependency Web Application Firewall written in Go" \
      org.opencontainers.image.source="https://github.com/guardianwaf/guardianwaf" \
      org.opencontainers.image.licenses="MIT"

RUN apk --no-cache add ca-certificates tzdata && \
    adduser -D -H -s /sbin/nologin guardianwaf && \
    mkdir -p /var/lib/guardianwaf/ai && \
    chown -R guardianwaf:guardianwaf /var/lib/guardianwaf

COPY --from=builder /app/guardianwaf /usr/local/bin/guardianwaf

WORKDIR /var/lib/guardianwaf
USER guardianwaf
EXPOSE 8088 8443 9443

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/guardianwaf", "version"]

ENTRYPOINT ["guardianwaf"]
CMD ["serve"]
