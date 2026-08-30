package raft

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// Cluster RPC authentication.
//
// The transport accepted any TCP connection and dispatched every frame straight
// to Raft.handleRPC: no shared secret, no MAC, no TLS, no peer allowlist. Since
// handleAppendEntries trusts the term and leader ID it is told, anyone able to
// reach the Raft port could claim leadership with an inflated term and drive the
// replicated state machine — whose commands are CmdBanIP, CmdUnbanIP, CmdSetRule
// and CmdDeleteRule. That is remote "delete every WAF rule across the fleet" or
// "ban the customer's own address range", from an unauthenticated socket.
//
// Every frame now carries an HMAC-SHA256 tag over the type, the payload, a
// random nonce and a timestamp. Frames without a valid tag are dropped before
// they reach the state machine, and the timestamp bounds replay.

const (
	// authNonceSize is the per-frame random nonce length.
	authNonceSize = 16
	// authTagSize is the HMAC-SHA256 output length.
	authTagSize = sha256.Size
	// authTimestampSize is the big-endian unix-nano timestamp length.
	authTimestampSize = 8
	// authTrailerSize is the total authentication trailer appended to a payload.
	authTrailerSize = authNonceSize + authTimestampSize + authTagSize

	// authMaxSkew bounds how far a frame's timestamp may sit from local time.
	// It has to tolerate ordinary NTP drift between nodes while keeping a
	// captured frame from being replayed indefinitely.
	authMaxSkew = 5 * time.Minute

	// MinSecretLen is the shortest accepted cluster secret. Raft peers
	// authenticate each other with this value alone, so it must carry real
	// entropy rather than be a memorable word.
	MinSecretLen = 32
)

// ErrUnauthenticated reports a frame whose authentication tag did not verify.
var ErrUnauthenticated = errors.New("raft rpc: frame authentication failed")

// ErrSecretRequired reports a transport configured without a usable secret.
var ErrSecretRequired = fmt.Errorf("raft transport: cluster secret must be at least %d bytes", MinSecretLen)

// validateSecret rejects absent or too-short secrets, so a cluster cannot be
// brought up unauthenticated by omitting configuration.
func validateSecret(secret []byte) error {
	if len(secret) < MinSecretLen {
		return ErrSecretRequired
	}
	return nil
}

// sealPayload appends a nonce, a timestamp and an HMAC tag to payload.
func sealPayload(secret []byte, msgType RPCType, payload []byte) ([]byte, error) {
	nonce := make([]byte, authNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("raft rpc: nonce: %w", err)
	}

	out := make([]byte, 0, len(payload)+authTrailerSize)
	out = append(out, payload...)
	out = append(out, nonce...)

	var ts [authTimestampSize]byte
	binary.BigEndian.PutUint64(ts[:], uint64(timeNow().UnixNano())) // #nosec G115 -- unix nanos are positive for any realistic clock
	out = append(out, ts[:]...)

	return append(out, computeTag(secret, msgType, out)...), nil
}

// openPayload verifies the trailer appended by sealPayload and returns the
// original payload.
func openPayload(secret []byte, msgType RPCType, framed []byte) ([]byte, error) {
	if len(framed) < authTrailerSize {
		return nil, ErrUnauthenticated
	}

	signed := framed[:len(framed)-authTagSize]
	tag := framed[len(framed)-authTagSize:]

	if !hmac.Equal(tag, computeTag(secret, msgType, signed)) {
		return nil, ErrUnauthenticated
	}

	tsOffset := len(signed) - authTimestampSize
	ts := int64(binary.BigEndian.Uint64(signed[tsOffset:])) // #nosec G115 -- round-trips the value written above
	if skew := timeNow().Sub(time.Unix(0, ts)); skew > authMaxSkew || skew < -authMaxSkew {
		return nil, fmt.Errorf("%w: timestamp outside %s skew window", ErrUnauthenticated, authMaxSkew)
	}

	return signed[:tsOffset-authNonceSize], nil
}

// computeTag binds the tag to the message type as well as the body, so a frame
// cannot be replayed as a different RPC.
func computeTag(secret []byte, msgType RPCType, body []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte{byte(msgType)}) // #nosec G115 -- RPCType is uint8
	_, _ = mac.Write(body)
	return mac.Sum(nil)
}

// EncodeAuthenticatedRequest writes an authenticated framed RPC message.
func EncodeAuthenticatedRequest(w io.Writer, secret []byte, msgType RPCType, payload []byte) error {
	if err := validateSecret(secret); err != nil {
		return err
	}
	sealed, err := sealPayload(secret, msgType, payload)
	if err != nil {
		return err
	}
	return EncodeRequest(w, msgType, sealed)
}

// ReadAuthenticatedFrame reads a framed RPC message and verifies its tag.
func ReadAuthenticatedFrame(r io.Reader, secret []byte) (RPCType, []byte, error) {
	if err := validateSecret(secret); err != nil {
		return 0, nil, err
	}
	msgType, framed, err := ReadFrame(r)
	if err != nil {
		return 0, nil, err
	}
	payload, err := openPayload(secret, msgType, framed)
	if err != nil {
		return 0, nil, err
	}
	return msgType, payload, nil
}

// timeNow is a seam for tests.
var timeNow = time.Now
