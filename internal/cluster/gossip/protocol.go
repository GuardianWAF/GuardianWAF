package gossip

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// shuffle randomises a slice in-place using math/rand/v2.
func shuffle[T any](s []T) {
	for i := len(s) - 1; i > 0; i-- {
		j := rand.IntN(i + 1) //nolint:gosec // G404 — not security-sensitive
		s[i], s[j] = s[j], s[i]
	}
}

// Config controls gossip protocol behavior.
type Config struct {
	NodeID           string        // unique identifier for this node
	Addr             string        // bind address (e.g., ":7946")
	RaftAddr         string        // Raft TCP address (e.g., ":7947") — propagated to peers via gossip
	DashboardAddr    string        // Dashboard HTTP address (e.g., ":8080") — propagated to peers via gossip
	ProbeInterval    time.Duration // how often to probe a random member
	ProbeTimeout     time.Duration // timeout for a single probe cycle
	IndirectChecks   int           // number of peers to ask for indirect-ping
	SuspicionTimeout time.Duration // how long before suspect → dead
	GossipInterval   time.Duration // how often to disseminate piggybacked state
	GossipFanout     int           // number of peers to gossip to per interval
	Logger           *slog.Logger

	// Secret authenticates every gossip datagram. It is required: a member
	// discovered over gossip is promoted into the Raft peer set, so an
	// unauthenticated socket lets one spoofed packet join the cluster.
	// Must be at least MinSecretLen bytes.
	Secret []byte
}

// DefaultConfig returns production-ready defaults.
func DefaultConfig(nodeID, addr string) Config {
	return Config{
		NodeID:           nodeID,
		Addr:             addr,
		ProbeInterval:    1 * time.Second,
		ProbeTimeout:     500 * time.Millisecond,
		IndirectChecks:   3,
		SuspicionTimeout: 5 * time.Second,
		GossipInterval:   200 * time.Millisecond,
		GossipFanout:     3,
		Logger:           slog.Default(),
	}
}

// Gossip is the membership protocol engine. It runs background goroutines
// for probing and dissemination, and handles incoming messages.
type Gossip struct {
	config    Config
	transport Transport
	members   *MemberList

	// incarnation number — bumped when we're marked suspect by a peer
	incarnation atomic.Uint64

	// piggyback queue — state updates waiting to be attached to outgoing messages
	piggybackMu sync.Mutex
	piggyback   []Member

	// sequence numbers
	seq atomic.Uint32

	// pending acks — seq → channel signaled when ack arrives
	acksMu sync.Mutex
	acks   map[uint32]chan struct{}

	// suspect→dead transition timers, tracked so Stop() can cancel them and
	// the onLeave callback (Raft peer-sync bridge) never fires post-shutdown
	timersMu sync.Mutex
	timers   map[string]*time.Timer
	stopped  atomic.Bool

	// lifecycle
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// callbacks for integration with higher-level cluster code
	onJoin  func(id, addr string)
	onLeave func(id string)

	logger *slog.Logger
}

// New creates a Gossip instance with a UDP transport bound to config.Addr.
func New(cfg Config) (*Gossip, error) {
	tr, err := NewUDPTransport(cfg.Addr)
	if err != nil {
		return nil, err
	}
	return NewWithTransport(cfg, tr)
}

// NewWithTransport creates a Gossip with a custom Transport (for testing).
func NewWithTransport(cfg Config, tr Transport) (*Gossip, error) {
	if cfg.NodeID == "" {
		return nil, errors.New("gossip: NodeID is required")
	}
	// Fail closed: a gossip node without a secret would accept membership
	// updates from anyone who can reach its UDP port.
	if err := validateSecret(cfg.Secret); err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	g := &Gossip{
		config:    cfg,
		transport: tr,
		members:   NewMemberList(cfg.NodeID),
		acks:      make(map[uint32]chan struct{}),
		timers:    make(map[string]*time.Timer),
		logger:    logger,
	}

	// Register self as alive.
	g.incarnation.Store(1)
	g.members.Add(Member{
		ID:            cfg.NodeID,
		Addr:          tr.LocalAddr(),
		RaftAddr:      cfg.RaftAddr,
		DashboardAddr: cfg.DashboardAddr,
		Incarnation:   1,
		State:         StateAlive,
	})

	return g, nil
}

// SetCallbacks registers join/leave callbacks invoked when members transition
// to alive (join) or dead (leave). These are used by the PeerSyncBridge to
// propagate membership changes to the Raft consensus layer.
func (g *Gossip) SetCallbacks(onJoin func(id, addr string), onLeave func(id string)) {
	g.onJoin = onJoin
	g.onLeave = onLeave
}

// Start launches background probe, gossip, and receive goroutines.
func (g *Gossip) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel

	g.wg.Add(3)
	go g.runReceiver(ctx)
	go g.runProber(ctx)
	go g.runGossip(ctx)

	g.logger.Info("gossip started", "node_id", g.config.NodeID, "addr", g.transport.LocalAddr())
	return nil
}

// Stop gracefully shuts down the protocol.
func (g *Gossip) Stop() {
	g.stopped.Store(true)

	// Cancel pending suspect→dead timers so the onLeave callback (Raft
	// peer-sync bridge) can never fire after shutdown.
	g.timersMu.Lock()
	for id, tm := range g.timers {
		tm.Stop()
		delete(g.timers, id)
	}
	g.timersMu.Unlock()

	if g.cancel != nil {
		g.cancel()
	}
	g.wg.Wait()
	g.transport.Close()
	g.logger.Info("gossip stopped", "node_id", g.config.NodeID)
}

// Members returns the current membership view.
func (g *Gossip) Members() []Member {
	return g.members.AllMembers()
}

// MemberCount returns the number of alive members (including self).
func (g *Gossip) MemberCount() int {
	return len(g.members.AliveMembers())
}

// LocalMember returns this node's member info.
func (g *Gossip) LocalMember() Member {
	m, _ := g.members.Get(g.config.NodeID)
	return m
}

// Incarnation returns the current incarnation number.
func (g *Gossip) Incarnation() uint64 {
	return g.incarnation.Load()
}

// IsLocalNode reports whether id is this node's own ID.
func (g *Gossip) IsLocalNode(id string) bool {
	return id == g.config.NodeID
}

// UpdateMember merges a member update from an external source (e.g. Raft
// state replication). Stale incarnations are ignored.
func (g *Gossip) UpdateMember(m Member) {
	wasNew := !g.members.Contains(m.ID)
	g.members.Add(m)
	g.enqueuePiggyback(m)
	if wasNew && m.State == StateAlive && g.onJoin != nil {
		g.onJoin(m.ID, m.Addr)
	}
	if m.State == StateDead && g.onLeave != nil {
		g.onLeave(m.ID)
	}
}

// PurgeDead removes dead members from the memberlist. Called periodically
// by the prober; also safe to call manually.
func (g *Gossip) PurgeDead() {
	g.members.PurgeDead()
}

// Leave announces departure by incrementing incarnation and marking self dead,
// then disseminates the state to peers.
func (g *Gossip) Leave() {
	inc := g.incarnation.Add(1)
	g.members.MarkDead(g.config.NodeID)
	g.enqueuePiggyback(Member{
		ID:          g.config.NodeID,
		Addr:        g.transport.LocalAddr(),
		Incarnation: inc,
		State:       StateDead,
	})
}

// Join attempts to contact known peers and exchange state.
// Each addr is "host:port". Returns the number of peers that responded.
func (g *Gossip) Join(addrs []string) int {
	joined := 0
	for _, addr := range addrs {
		if addr == g.transport.LocalAddr() {
			continue
		}
		// Send a push-pull message to exchange full state.
		if err := g.sendPushPull(addr); err != nil {
			g.logger.Debug("join: push-pull failed", "addr", addr, "err", err)
			continue
		}
		joined++
	}
	g.logger.Info("join complete", "contacted", len(addrs), "responded", joined)
	return joined
}

// OnJoin sets a callback fired when a new member joins (first time seen alive).
func (g *Gossip) OnJoin(fn func(id, addr string)) { g.onJoin = fn }

// OnLeave sets a callback fired when a member transitions to dead.
func (g *Gossip) OnLeave(fn func(id string)) { g.onLeave = fn }

// ---------------------------------------------------------------------------
// Piggyback queue — state updates attached to outgoing messages
// ---------------------------------------------------------------------------

func (g *Gossip) enqueuePiggyback(m Member) {
	g.piggybackMu.Lock()
	defer g.piggybackMu.Unlock()
	// Deduplicate: if the same member ID is already queued, replace with
	// the newer incarnation (keep the freshest state).
	for i, existing := range g.piggyback {
		if existing.ID == m.ID {
			if m.Incarnation >= existing.Incarnation {
				g.piggyback[i] = m
			}
			return
		}
	}
	// Cap the queue to avoid unbounded growth.
	if len(g.piggyback) >= maxPiggybackQueue {
		g.piggyback = g.piggyback[1:]
	}
	g.piggyback = append(g.piggyback, m)
}

// takePiggyback encodes up to maxPiggybackPerMsg pending state updates into a
// byte slice and removes them from the queue. Returns nil when empty.
func (g *Gossip) takePiggyback() []byte {
	g.piggybackMu.Lock()
	defer g.piggybackMu.Unlock()

	n := len(g.piggyback)
	if n == 0 {
		return nil
	}
	if n > maxPiggybackPerMsg {
		n = maxPiggybackPerMsg
	}
	taken := make([]Member, n)
	copy(taken, g.piggyback[:n])
	g.piggyback = g.piggyback[n:]
	return EncodeMembers(taken)
}

const (
	maxPiggybackQueue  = 256
	maxPiggybackPerMsg = 6
)

// ---------------------------------------------------------------------------
// Background loops
// ---------------------------------------------------------------------------

func (g *Gossip) runReceiver(ctx context.Context) {
	defer g.wg.Done()
	for {
		data, from, err := g.transport.Receive(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, netClosedErr{}) {
				return
			}
			g.logger.Debug("receive error", "err", err)
			continue
		}
		body, authErr := open(g.config.Secret, data)
		if authErr != nil {
			// Anyone can send this socket a UDP packet; only peers holding the
			// cluster secret get to influence membership.
			g.logger.Debug("rejected unauthenticated datagram", "from", from, "err", authErr)
			continue
		}
		g.handleMessage(body, from)
	}
}

func (g *Gossip) runProber(ctx context.Context) {
	defer g.wg.Done()
	ticker := time.NewTicker(g.config.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.probeCycle()
		}
	}
}

func (g *Gossip) runGossip(ctx context.Context) {
	defer g.wg.Done()
	ticker := time.NewTicker(g.config.GossipInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.disseminate()
		}
	}
}

// ---------------------------------------------------------------------------
// Probing
// ---------------------------------------------------------------------------

func (g *Gossip) probeCycle() {
	target, ok := g.members.RandomMember(g.config.NodeID)
	if !ok {
		return
	}

	if g.directProbe(target.Addr) {
		return
	}

	// Direct probe failed — try indirect probes via random peers.
	g.indirectProbe(target)
}

func (g *Gossip) directProbe(addr string) bool {
	seq := g.nextSeq()
	ackCh := g.registerAck(seq)
	defer g.unregisterAck(seq)

	payload := g.takePiggyback()
	g.send(addr, Message{Seq: seq, Type: TypePing, Source: g.config.NodeID, Payload: payload})

	select {
	case <-ackCh:
		return true
	case <-time.After(g.config.ProbeTimeout):
		return false
	}
}

func (g *Gossip) indirectProbe(target Member) {
	// Pick N random alive peers (excluding self and target).
	peers := g.randomPeers(g.config.IndirectChecks, target.ID)
	if len(peers) == 0 {
		g.markSuspect(target.ID)
		return
	}

	seq := g.nextSeq()
	// PingReq payload is just the target address — piggyback state is
	// disseminated by the separate disseminate() goroutine to avoid
	// corrupting the address with member-encoded bytes.
	payload := []byte(target.Addr)

	for _, p := range peers {
		g.send(p.Addr, Message{Seq: seq, Type: TypePingReq, Source: g.config.NodeID, Payload: payload})
	}

	// Wait for an indirect ack with a bounded timeout.
	ackCh := g.registerAck(seq)
	defer g.unregisterAck(seq)
	select {
	case <-ackCh:
		// Indirect probe succeeded — node is alive.
	case <-time.After(g.config.ProbeTimeout * 2):
		g.markSuspect(target.ID)
	}
}

func (g *Gossip) markSuspect(id string) {
	if g.stopped.Load() {
		return
	}
	if !g.members.MarkSuspect(id) {
		return
	}
	m, _ := g.members.Get(id)
	g.logger.Info("member suspected", "id", id, "incarnation", m.Incarnation)
	g.enqueuePiggyback(m)

	// Schedule the dead transition after the suspicion timeout. The timer is
	// tracked per member and cancelled in Stop() so the suspect→dead
	// transition and the onLeave callback (Raft peer-sync bridge) can never
	// fire after shutdown.
	g.timersMu.Lock()
	if old, ok := g.timers[id]; ok {
		old.Stop()
	}
	g.timers[id] = time.AfterFunc(g.config.SuspicionTimeout, func() {
		defer func() {
			g.timersMu.Lock()
			delete(g.timers, id)
			g.timersMu.Unlock()
		}()
		if g.stopped.Load() {
			return
		}
		if cur, ok := g.members.Get(id); ok && cur.State == StateSuspect {
			if g.members.MarkDead(id) {
				g.logger.Info("member dead", "id", id)
				g.enqueuePiggyback(Member{ID: id, Addr: cur.Addr, Incarnation: cur.Incarnation, State: StateDead})
				if g.onLeave != nil {
					g.onLeave(id)
				}
			}
		}
	})
	g.timersMu.Unlock()
}

// ---------------------------------------------------------------------------
// Dissemination
// ---------------------------------------------------------------------------

func (g *Gossip) disseminate() {
	pb := g.takePiggyback()
	if len(pb) == 0 {
		return
	}
	encoded := pb
	fanout := g.config.GossipFanout
	if fanout < 1 {
		fanout = 1
	}
	peers := g.randomPeers(fanout, "")
	for _, p := range peers {
		seq := g.nextSeq()
		g.send(p.Addr, Message{Seq: seq, Type: TypeAlive, Source: g.config.NodeID, Payload: encoded})
	}
}

func (g *Gossip) sendPushPull(addr string) error {
	allMembers := g.members.AllMembers()
	payload := EncodeMembers(allMembers)
	seq := g.nextSeq()
	ackCh := g.registerAck(seq)
	defer g.unregisterAck(seq)

	g.send(addr, Message{Seq: seq, Type: TypePushPull, Source: g.config.NodeID, Payload: payload})

	select {
	case <-ackCh:
		return nil
	case <-time.After(g.config.ProbeTimeout * 2):
		return errors.New("push-pull timeout")
	}
}

// ---------------------------------------------------------------------------
// Message handling
// ---------------------------------------------------------------------------

func (g *Gossip) handleMessage(data []byte, from string) {
	msg, err := DecodeMessageBytes(data)
	if err != nil {
		g.logger.Debug("decode error", "from", from, "err", err)
		return
	}

	// Process piggybacked state regardless of message type.
	g.applyPiggyback(msg.Payload)

	switch msg.Type {
	case TypePing:
		g.handlePing(msg, from)
	case TypeAck:
		g.handleAck(msg)
	case TypePingReq:
		g.handlePingReq(msg)
	case TypeAlive:
		// State already applied via piggyback processing.
	case TypeSuspect:
		// State already applied via piggyback processing.
	case TypeDead:
		// State already applied via piggyback processing.
	case TypePushPull:
		g.handlePushPull(msg, from)
	default:
		g.logger.Debug("unknown message type", "type", msg.Type, "from", from)
	}
}

func (g *Gossip) handlePing(msg *Message, from string) {
	// Send an ack back with our piggybacked state.
	payload := g.takePiggyback()
	g.send(from, Message{Seq: msg.Seq, Type: TypeAck, Source: g.config.NodeID, Payload: payload})
}

func (g *Gossip) handleAck(msg *Message) {
	// Ack payloads from push-pull carry the responder's full member list.
	// applyPiggyback already processed msg.Payload before we get here.
	g.signalAck(msg.Seq)
}

func (g *Gossip) handlePingReq(msg *Message) {
	// Payload starts with the target address, followed by piggyback data.
	if len(msg.Payload) == 0 {
		return
	}
	// Extract the target address (first null-terminated or just the first field).
	// We encoded it as a plain string in indirectProbe.
	targetAddr := string(msg.Payload)
	// Actually, the target addr was prepended raw. Let's use it directly.
	// But piggyback data follows — we need a delimiter. Let's use the original
	// approach: the payload is just the target addr for ping-req.
	// (Piggyback was already processed above.)

	// Do a direct probe to the target on behalf of the requester.
	if g.directProbe(targetAddr) {
		// Target responded — send an ack back to the original requester.
		g.send(msg.Source, Message{Seq: msg.Seq, Type: TypeAck, Source: g.config.NodeID})
	}
}

func (g *Gossip) handlePushPull(msg *Message, from string) {
	// The piggyback processing already merged the remote state.
	// Send an ack with our full state as the response payload.
	allMembers := g.members.AllMembers()
	payload := EncodeMembers(allMembers)
	g.send(from, Message{Seq: msg.Seq, Type: TypeAck, Source: g.config.NodeID, Payload: payload})
}

// applyPiggyback decodes and merges piggybacked member updates from a message payload.
func (g *Gossip) applyPiggyback(payload []byte) {
	if len(payload) == 0 {
		return
	}
	updates, err := DecodeMembers(payload)
	if err != nil {
		g.logger.Debug("decode piggyback", "err", err)
		return
	}
	for _, m := range updates {
		if m.ID == g.config.NodeID {
			// Someone thinks we're suspect/dead — refute by bumping incarnation.
			if m.State != StateAlive && m.Incarnation >= g.incarnation.Load() {
				newInc := m.Incarnation + 1
				g.incarnation.Store(newInc)
				refutation := Member{
					ID:          g.config.NodeID,
					Addr:        g.transport.LocalAddr(),
					Incarnation: newInc,
					State:       StateAlive,
				}
				g.members.Add(refutation)
				g.enqueuePiggyback(refutation)
				g.logger.Info("refuted suspicion", "incarnation", newInc)
			}
			continue
		}

		wasNew := !g.members.Contains(m.ID)
		accepted := g.members.Add(m)
		if accepted || wasNew {
			g.enqueuePiggyback(m)
		}

		if wasNew && m.State == StateAlive && g.onJoin != nil {
			g.onJoin(m.ID, m.Addr)
		}
		if m.State == StateDead && g.onLeave != nil {
			g.onLeave(m.ID)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func (g *Gossip) nextSeq() uint32 {
	return g.seq.Add(1)
}

func (g *Gossip) send(addr string, msg Message) {
	data, err := msg.EncodeMessage()
	if err != nil {
		g.logger.Debug("encode error", "err", err)
		return
	}
	sealed, err := seal(g.config.Secret, data)
	if err != nil {
		g.logger.Debug("seal error", "err", err)
		return
	}
	if err := g.transport.Send(addr, sealed); err != nil {
		g.logger.Debug("send error", "addr", addr, "err", err)
	}
}

func (g *Gossip) registerAck(seq uint32) chan struct{} {
	ch := make(chan struct{}, 1)
	g.acksMu.Lock()
	g.acks[seq] = ch
	g.acksMu.Unlock()
	return ch
}

func (g *Gossip) unregisterAck(seq uint32) {
	g.acksMu.Lock()
	delete(g.acks, seq)
	g.acksMu.Unlock()
}

func (g *Gossip) signalAck(seq uint32) {
	g.acksMu.Lock()
	ch, ok := g.acks[seq]
	g.acksMu.Unlock()
	if ok {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// randomPeers returns up to n random alive members excluding excludeID.
func (g *Gossip) randomPeers(n int, excludeID string) []Member {
	all := g.members.AliveMembers()
	var candidates []Member
	for _, id := range all {
		if id == excludeID || id == g.config.NodeID {
			continue
		}
		m, ok := g.members.Get(id)
		if ok {
			candidates = append(candidates, m)
		}
	}
	shuffle(candidates)
	if n > len(candidates) {
		n = len(candidates)
	}
	return candidates[:n]
}

// netClosedErr is a sentinel for transport-closed errors.
type netClosedErr struct{}

func (netClosedErr) Error() string { return "transport closed" }
