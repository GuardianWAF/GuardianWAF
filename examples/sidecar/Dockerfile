# GuardianWAF Sidecar — lightweight proxy mode (no dashboard/MCP)
# Build from repo root: docker build -f examples/sidecar/Dockerfile -t guardianwaf-sidecar .
FROM golang:1.25.0-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o guardianwaf ./cmd/guardianwaf

FROM alpine:3.21
RUN apk --no-cache add ca-certificates && \
    adduser -D -H -s /sbin/nologin guardianwaf
COPY --from=builder /app/guardianwaf /usr/local/bin/guardianwaf
USER guardianwaf
EXPOSE 8088
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8088/healthz || exit 1
ENTRYPOINT ["guardianwaf"]
CMD ["sidecar", "--upstream", "http://localhost:3000"]
