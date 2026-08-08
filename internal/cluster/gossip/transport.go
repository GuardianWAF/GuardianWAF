package gossip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// Transport is the interface for sending and receiving gossip messages.
type Transport interface {
	Send(addr string, data []byte) error
	Receive(ctx context.Context) ([]byte, string, error)
	LocalAddr() string
	Close() error
}

// ---------------------------------------------------------------------------
// UDP transport (production)
// ---------------------------------------------------------------------------

// UDPTransport implements Transport over UDP.
type UDPTransport struct {
	conn *net.UDPConn
}

// NewUDPTransport binds a UDP socket. Pass ":0" for an ephemeral port.
func NewUDPTransport(addr string) (*UDPTransport, error) {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("gossip: resolve %s: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return nil, fmt.Errorf("gossip: listen udp %s: %w", addr, err)
	}
	_ = conn.SetReadBuffer(1 << 20)
	return &UDPTransport{conn: conn}, nil
}

func (t *UDPTransport) LocalAddr() string {
	if t.conn == nil {
		return ""
	}
	return t.conn.LocalAddr().String()
}

func (t *UDPTransport) Send(addr string, data []byte) error {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("gossip: resolve %s: %w", addr, err)
	}
	_, err = t.conn.WriteToUDP(data, uaddr)
	return err
}

func (t *UDPTransport) Receive(ctx context.Context) ([]byte, string, error) {
	buf := make([]byte, 65507)
	for {
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		default:
		}
		_ = t.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, src, err := t.conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return nil, "", err
		}
		out := make([]byte, n)
		copy(out, buf[:n])
		return out, src.String(), nil
	}
}

func (t *UDPTransport) Close() error {
	if t.conn == nil {
		return nil
	}
	return t.conn.Close()
}
