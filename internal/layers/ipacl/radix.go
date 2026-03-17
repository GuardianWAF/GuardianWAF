package ipacl

import (
	"fmt"
	"net"
	"sync"
)

// RadixTree stores IP addresses and CIDR ranges for fast O(k) lookup.
type RadixTree struct {
	mu    sync.RWMutex
	root  *radixNode
	count int
}

type radixNode struct {
	children [2]*radixNode // 0 and 1 branches
	value    interface{}   // stored value (nil for intermediate nodes)
	hasValue bool          // distinguishes nil value from no value
	prefix   int           // prefix length at this node
}

// NewRadixTree creates a new empty radix tree.
func NewRadixTree() *RadixTree {
	return &RadixTree{
		root: &radixNode{},
	}
}

// Insert adds an IP or CIDR to the tree.
// Supports both IPv4 (e.g., "192.168.1.1", "10.0.0.0/8") and IPv6.
func (t *RadixTree) Insert(cidr string, value interface{}) error {
	ip, network, err := parseCIDROrIP(cidr)
	if err != nil {
		return err
	}

	bits := ipToBits(ip)
	prefixLen, _ := network.Mask.Size()

	t.mu.Lock()
	defer t.mu.Unlock()

	node := t.root
	for i := 0; i < prefixLen; i++ {
		bit := bits[i]
		if node.children[bit] == nil {
			node.children[bit] = &radixNode{}
		}
		node = node.children[bit]
	}

	if !node.hasValue {
		t.count++
	}
	node.value = value
	node.hasValue = true
	node.prefix = prefixLen

	return nil
}

// Lookup checks if the given IP matches any entry in the tree.
// Returns the value and true if found, nil and false otherwise.
// Uses longest prefix match - walks the tree and returns the deepest match.
func (t *RadixTree) Lookup(ip net.IP) (interface{}, bool) {
	// Normalize to 16-byte form
	normalized := ip.To16()
	if normalized == nil {
		return nil, false
	}

	// If it's an IPv4 address, also try the 4-byte form for matching
	// We store based on how parseCIDROrIP normalizes, so we should match consistently
	bits := ipToBits(normalized)

	t.mu.RLock()
	defer t.mu.RUnlock()

	var lastValue interface{}
	found := false

	node := t.root
	if node.hasValue {
		lastValue = node.value
		found = true
	}

	for i := 0; i < len(bits); i++ {
		bit := bits[i]
		child := node.children[bit]
		if child == nil {
			break
		}
		node = child
		if node.hasValue {
			lastValue = node.value
			found = true
		}
	}

	return lastValue, found
}

// Remove removes a CIDR from the tree.
func (t *RadixTree) Remove(cidr string) error {
	ip, network, err := parseCIDROrIP(cidr)
	if err != nil {
		return err
	}

	bits := ipToBits(ip)
	prefixLen, _ := network.Mask.Size()

	t.mu.Lock()
	defer t.mu.Unlock()

	node := t.root
	for i := 0; i < prefixLen; i++ {
		bit := bits[i]
		if node.children[bit] == nil {
			return fmt.Errorf("cidr %s not found in tree", cidr)
		}
		node = node.children[bit]
	}

	if !node.hasValue {
		return fmt.Errorf("cidr %s not found in tree", cidr)
	}

	node.value = nil
	node.hasValue = false
	t.count--

	return nil
}

// Len returns the number of entries.
func (t *RadixTree) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.count
}

// parseCIDROrIP parses a string as either a CIDR or a bare IP address.
// Bare IPs are treated as /32 (IPv4) or /128 (IPv6).
// All IPs are normalized to 16-byte IPv6 form for consistent tree storage.
func parseCIDROrIP(s string) (net.IP, *net.IPNet, error) {
	// Try as CIDR first
	ip, network, err := net.ParseCIDR(s)
	if err == nil {
		// Normalize the network IP to 16-byte form
		ip = network.IP.To16()
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid IP in CIDR: %s", s)
		}
		// Adjust mask for IPv4 CIDRs: net.ParseCIDR for "10.0.0.0/8" gives a 4-byte mask
		// We need to map to the IPv6-mapped equivalent
		ones, bits := network.Mask.Size()
		if bits == 32 {
			// IPv4 CIDR: shift prefix into IPv6-mapped space
			ones += 96
		}
		mask := net.CIDRMask(ones, 128)
		network = &net.IPNet{IP: ip, Mask: mask}
		return ip, network, nil
	}

	// Try as bare IP
	parsed := net.ParseIP(s)
	if parsed == nil {
		return nil, nil, fmt.Errorf("invalid IP or CIDR: %s", s)
	}
	ip = parsed.To16()
	if ip == nil {
		return nil, nil, fmt.Errorf("invalid IP: %s", s)
	}
	mask := net.CIDRMask(128, 128)
	network = &net.IPNet{IP: ip, Mask: mask}
	return ip, network, nil
}

// ipToBits converts a net.IP to a slice of bits (0 or 1).
// Always normalizes to 16-byte (128-bit) form.
func ipToBits(ip net.IP) []byte {
	ip = ip.To16()
	if ip == nil {
		return nil
	}
	bits := make([]byte, 128)
	for i := 0; i < 16; i++ {
		for j := 7; j >= 0; j-- {
			if ip[i]&(1<<uint(j)) != 0 {
				bits[i*8+(7-j)] = 1
			}
		}
	}
	return bits
}
