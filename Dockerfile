FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w \
    -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo dev) \
    -X main.commit=$(git rev-parse --short HEAD 2>/dev/null || echo none) \
    -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o guardianwaf ./cmd/guardianwaf

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/guardianwaf /usr/local/bin/guardianwaf
EXPOSE 8080 9443
ENTRYPOINT ["guardianwaf"]
CMD ["serve"]
