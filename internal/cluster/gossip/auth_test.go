package gossip

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// fakeTransport is an inert Transport for constructor tests.
type fakeTransport struct{}

func (fakeTransport) Send(string, []byte) error { return nil }
func (fakeTransport) Receive(ctx context.Context) ([]byte, string, error) {
	<-ctx.Done()
	return nil, "", ctx.Err()
}
func (fakeTransport) LocalAddr() string { return "127.0.0.1:0" }
func (fakeTransport) Close() error      { return nil }

// TestNewRequiresSecret pins the fail-closed constructor. A gossip node with no
// secret accepted membership updates from anyone able to send it a UDP packet,
// and peersync promotes a discovered member straight into the Raft peer set.
func TestNewRequiresSecret(t *testing.T) {
	for _, secret := range [][]byte{nil, {}, []byte("short")} {
		cfg := DefaultConfig("node-a", "127.0.0.1:0")
		cfg.Secret = secret
		if _, err := NewWithTransport(cfg, &fakeTransport{}); !errors.Is(err, ErrSecretRequired) {
			t.Fatalf("NewWithTransport with %d-byte secret: err = %v, want ErrSecretRequired", len(secret), err)
		}
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	body := []byte(`{"type":"ping","node":"node-a"}`)

	sealed, err := seal(testSecret, body)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := open(testSecret, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("round trip = %q, want %q", got, body)
	}

	t.Run("wrong secret is rejected", func(t *testing.T) {
		if _, err := open([]byte("a-different-cluster-secret-0123456789"), sealed); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("err = %v, want ErrUnauthenticated", err)
		}
	})

	t.Run("tampered datagram is rejected", func(t *testing.T) {
		bad := bytes.Clone(sealed)
		bad[0] ^= 0xFF
		if _, err := open(testSecret, bad); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("err = %v, want ErrUnauthenticated", err)
		}
	})

	t.Run("unauthenticated datagram is rejected", func(t *testing.T) {
		if _, err := open(testSecret, body); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("a raw unsigned datagram was accepted: err = %v", err)
		}
	})

	t.Run("stale datagram is rejected", func(t *testing.T) {
		restore := timeNow
		timeNow = func() time.Time { return restore().Add(authMaxSkew + time.Minute) }
		defer func() { timeNow = restore }()

		if _, err := open(testSecret, sealed); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("err = %v, want ErrUnauthenticated", err)
		}
	})
}
