package gossip

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Gossip datagram authentication.
//
// The UDP socket accepted any datagram and fed it to handleMessage, and
// peersync promotes a gossip-discovered member straight into the Raft peer set.
// A single spoofed UDP packet therefore joined an attacker's address to the
// cluster, after which the (previously unauthenticated) Raft port gave them the
// replicated ban and rule state. Every datagram now carries an HMAC-SHA256 tag
// over the body, a random nonce and a timestamp.
//
// UDP is unordered and lossy, so this deliberately does not keep a replay
// cache: the timestamp window bounds replay, and the membership protocol is
// already idempotent with respect to duplicated messages.

const (
	authNonceSize     = 16
	authTagSize       = sha256.Size
	authTimestampSize = 8
	authTrailerSize   = authNonceSize + authTimestampSize + authTagSize

	// authMaxSkew tolerates NTP drift between nodes while bounding replay.
	authMaxSkew = 5 * time.Minute

	// MinSecretLen is the shortest accepted cluster secret.
	MinSecretLen = 32
)

// ErrUnauthenticated reports a datagram whose tag did not verify.
var ErrUnauthenticated = errors.New("gossip: datagram authentication failed")

// ErrSecretRequired reports a gossip node configured without a usable secret.
var ErrSecretRequired = fmt.Errorf("gossip: cluster secret must be at least %d bytes", MinSecretLen)

// validateSecret rejects absent or too-short secrets.
func validateSecret(secret []byte) error {
	if len(secret) < MinSecretLen {
		return ErrSecretRequired
	}
	return nil
}

// seal appends a nonce, timestamp and HMAC tag to a gossip datagram.
func seal(secret, body []byte) ([]byte, error) {
	nonce := make([]byte, authNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("gossip: nonce: %w", err)
	}

	out := make([]byte, 0, len(body)+authTrailerSize)
	out = append(out, body...)
	out = append(out, nonce...)

	var ts [authTimestampSize]byte
	binary.BigEndian.PutUint64(ts[:], uint64(timeNow().UnixNano())) // #nosec G115 -- unix nanos are positive
	out = append(out, ts[:]...)

	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(out)
	return mac.Sum(out), nil
}

// open verifies a datagram's trailer and returns the original body.
func open(secret, datagram []byte) ([]byte, error) {
	if len(datagram) < authTrailerSize {
		return nil, ErrUnauthenticated
	}

	signed := datagram[:len(datagram)-authTagSize]
	tag := datagram[len(datagram)-authTagSize:]

	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(signed)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return nil, ErrUnauthenticated
	}

	tsOffset := len(signed) - authTimestampSize
	ts := int64(binary.BigEndian.Uint64(signed[tsOffset:])) // #nosec G115 -- round-trips the written value
	if skew := timeNow().Sub(time.Unix(0, ts)); skew > authMaxSkew || skew < -authMaxSkew {
		return nil, fmt.Errorf("%w: timestamp outside %s skew window", ErrUnauthenticated, authMaxSkew)
	}

	return signed[:tsOffset-authNonceSize], nil
}

// timeNow is a seam for tests.
var timeNow = time.Now
