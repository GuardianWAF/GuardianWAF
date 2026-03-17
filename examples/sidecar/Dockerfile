FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY ../../go.mod ./
RUN go mod download
COPY ../.. .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o guardianwaf ./cmd/guardianwaf

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/guardianwaf /usr/local/bin/guardianwaf
EXPOSE 8080
ENTRYPOINT ["guardianwaf"]
CMD ["sidecar", "--upstream", "http://localhost:3000"]
