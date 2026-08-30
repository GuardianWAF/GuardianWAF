package raft

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Dialer abstracts net.Dial so tests can substitute in-memory connections.
type Dialer func(network, addr string) (net.Conn, error)

// TCPTransport implements Transport over TCP with per-peer connection pooling.
// Each peer gets a dedicated long-lived connection. Writes are serialized per
// peer via a mutex to avoid interleaved frames on the wire.
type TCPTransport struct {
	peerMu   map[string]*sync.Mutex // per-peer write serialization
	peerMuMu sync.Mutex             // protects peerMu map
	conns    map[string]net.Conn    // peerAddr -> connection
	connMu   sync.Mutex             // protects conns map
	dialer   Dialer
	listener net.Listener
	localID  string
	timeout  time.Duration

	// handler is called for every incoming RPC. It runs in the reader
	// goroutine of the connection, so it must not block.
	handler func(msgType RPCType, payload []byte) ([]byte, error)

	// secret authenticates every frame in both directions. Without it any
	// host able to reach the listener could drive the replicated state
	// machine, so the transport refuses to start without one.
	secret []byte
}

// NewTCPTransport creates a TCP transport listening on addr.
//
// secret authenticates every RPC frame and is mandatory: the Raft log carries
// ban and rule mutations, so an unauthenticated listener is remote control of
// the WAF fleet. It must be at least MinSecretLen bytes.
func NewTCPTransport(addr, localID string, timeout time.Duration, secret []byte) (*TCPTransport, error) {
	if err := validateSecret(secret); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("raft transport: listen %s: %w", addr, err)
	}
	t := &TCPTransport{
		conns:    make(map[string]net.Conn),
		peerMu:   make(map[string]*sync.Mutex),
		dialer:   net.Dial,
		listener: ln,
		localID:  localID,
		timeout:  timeout,
		secret:   append([]byte(nil), secret...),
	}
	return t, nil
}

// SetDialer replaces the dialer used for outbound connections and drops all
// existing pooled connections. Intended for testing (e.g., to simulate
// network partitions by swapping in a dialer that refuses certain peers).
func (t *TCPTransport) SetDialer(d Dialer) {
	t.connMu.Lock()
	for _, conn := range t.conns {
		conn.Close()
	}
	t.conns = make(map[string]net.Conn)
	t.dialer = d
	t.connMu.Unlock()
}

// LocalAddr returns the transport's listen address.
func (t *TCPTransport) LocalAddr() string {
	return t.listener.Addr().String()
}

// SetHandler registers the RPC handler. Must be called before Start.
func (t *TCPTransport) SetHandler(h func(RPCType, []byte) ([]byte, error)) {
	t.handler = h
}

// Start begins accepting inbound connections.
func (t *TCPTransport) Start() error {
	go t.acceptLoop()
	return nil
}

func (t *TCPTransport) acceptLoop() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			return // listener closed
		}
		go t.handleConn(conn)
	}
}

func (t *TCPTransport) handleConn(conn net.Conn) {
	defer conn.Close()
	for {
		if t.timeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(t.timeout * 10)) // generous read deadline
		}
		msgType, payload, err := ReadAuthenticatedFrame(conn, t.secret)
		if err != nil {
			// An unauthenticated or replayed frame means this peer does not
			// share the cluster secret. Drop the connection rather than
			// answering, so a prober learns nothing about the protocol.
			return
		}

		if t.handler == nil {
			continue
		}

		resp, err := t.handler(msgType, payload)
		if err != nil {
			// Send an empty error response
			_ = EncodeAuthenticatedRequest(conn, t.secret, RPCError, nil)
			continue
		}
		// Determine response type: for RequestVote → RequestVoteResponse, etc.
		respType := RPCError
		switch msgType {
		case RPCRequestVoteRequest:
			respType = RPCRequestVoteResponse
		case RPCAppendEntriesRequest:
			respType = RPCAppendEntriesResponse
		}
		if resp != nil {
			_ = EncodeAuthenticatedRequest(conn, t.secret, respType, resp)
		} else {
			_ = EncodeAuthenticatedRequest(conn, t.secret, respType, nil)
		}
	}
}

// peerLock returns the mutex for a specific peer, creating it if needed.
func (t *TCPTransport) peerLock(addr string) *sync.Mutex {
	t.peerMuMu.Lock()
	defer t.peerMuMu.Unlock()
	mu, ok := t.peerMu[addr]
	if !ok {
		mu = &sync.Mutex{}
		t.peerMu[addr] = mu
	}
	return mu
}

// getConn returns (and lazily creates) a pooled connection to a peer.
func (t *TCPTransport) getConn(addr string) (net.Conn, error) {
	t.connMu.Lock()
	conn, ok := t.conns[addr]
	t.connMu.Unlock()
	if ok {
		return conn, nil
	}

	conn, err := t.dialer("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("raft transport: dial %s: %w", addr, err)
	}

	t.connMu.Lock()
	t.conns[addr] = conn
	t.connMu.Unlock()

	return conn, nil
}

// SendRPC sends a request to addr and waits for the response.
// Per-peer locking allows concurrent RPCs to different peers.
func (t *TCPTransport) SendRPC(addr string, msgType RPCType, payload []byte) (RPCType, []byte, error) {
	mu := t.peerLock(addr)
	mu.Lock()
	defer mu.Unlock()

	conn, err := t.getConn(addr)
	if err != nil {
		return 0, nil, err
	}

	if t.timeout > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(t.timeout))
	}

	if encodeErr := EncodeAuthenticatedRequest(conn, t.secret, msgType, payload); encodeErr != nil {
		t.dropConn(addr)
		return 0, nil, encodeErr
	}

	// Read the response frame.
	if t.timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(t.timeout))
	}
	respType, respPayload, err := ReadAuthenticatedFrame(conn, t.secret)
	if err != nil {
		t.dropConn(addr)
		return 0, nil, err
	}

	return respType, respPayload, nil
}

func (t *TCPTransport) dropConn(addr string) {
	t.connMu.Lock()
	defer t.connMu.Unlock()
	if conn, ok := t.conns[addr]; ok {
		conn.Close()
		delete(t.conns, addr)
	}
}

// Close shuts down the listener and all pooled connections.
func (t *TCPTransport) Close() error {
	if t.listener != nil {
		t.listener.Close()
	}
	t.connMu.Lock()
	for _, conn := range t.conns {
		conn.Close()
	}
	t.conns = make(map[string]net.Conn)
	t.connMu.Unlock()
	return nil
}
