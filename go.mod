module github.com/guardianwaf/guardianwaf

go 1.25.0

require github.com/quic-go/quic-go v0.59.0

require (
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
)

// quic-go is only needed when building with http3 tag
// Build with: go build -tags http3
