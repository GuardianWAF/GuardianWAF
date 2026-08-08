package raft

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Wire format: <type:1><len:4><payload:len>
// len is the payload length in bytes (uint32 big-endian).
// This mirrors the gossip wire format for consistency.

const maxFrameSize = 16 * 1024 * 1024 // 16 MiB safety cap

// EncodeRequest writes a framed RPC message to w.
// payload must be nil, a []byte already encoded by the caller, or a value
// that json.Marshal can handle. For clarity, callers should pass []byte.
func EncodeRequest(w io.Writer, msgType RPCType, payload []byte) error {
	var buf [5]byte
	buf[0] = byte(msgType)                                     // #nosec G115 -- RPCType is uint8, fits in byte
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload))) // #nosec G115 -- len fits in uint32 (checked by maxFrameSize)

	if _, err := w.Write(buf[:]); err != nil {
		return fmt.Errorf("raft rpc: write header: %w", err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return fmt.Errorf("raft rpc: write payload: %w", err)
		}
	}
	return nil
}

// ReadFrame reads a single framed RPC message from r.
// Returns the message type and the raw payload bytes.
func ReadFrame(r io.Reader) (RPCType, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}

	msgType := RPCType(header[0]) // #nosec G115 -- byte → RPCType (uint8), safe
	payloadLen := binary.BigEndian.Uint32(header[1:5])

	if payloadLen > maxFrameSize {
		return 0, nil, fmt.Errorf("raft rpc: frame too large: %d > %d", payloadLen, maxFrameSize)
	}

	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}

	return msgType, payload, nil
}

// EncodeRequestVote encodes a RequestVoteRequest as JSON.
func EncodeRequestVote(req RequestVoteRequest) ([]byte, error) {
	return json.Marshal(req)
}

// DecodeRequestVote decodes a RequestVoteRequest from JSON.
func DecodeRequestVote(data []byte) (RequestVoteRequest, error) {
	var req RequestVoteRequest
	err := json.Unmarshal(data, &req)
	return req, err
}

// EncodeRequestVoteResp encodes a RequestVoteResponse as JSON.
func EncodeRequestVoteResp(resp RequestVoteResponse) ([]byte, error) {
	return json.Marshal(resp)
}

// DecodeRequestVoteResp decodes a RequestVoteResponse from JSON.
func DecodeRequestVoteResp(data []byte) (RequestVoteResponse, error) {
	var resp RequestVoteResponse
	err := json.Unmarshal(data, &resp)
	return resp, err
}

// EncodeAppendEntries encodes an AppendEntriesRequest as JSON.
func EncodeAppendEntries(req AppendEntriesRequest) ([]byte, error) {
	return json.Marshal(req)
}

// DecodeAppendEntries decodes an AppendEntriesRequest from JSON.
func DecodeAppendEntries(data []byte) (AppendEntriesRequest, error) {
	var req AppendEntriesRequest
	err := json.Unmarshal(data, &req)
	return req, err
}

// EncodeAppendEntriesResp encodes an AppendEntriesResponse as JSON.
func EncodeAppendEntriesResp(resp AppendEntriesResponse) ([]byte, error) {
	return json.Marshal(resp)
}

// DecodeAppendEntriesResp decodes an AppendEntriesResponse from JSON.
func DecodeAppendEntriesResp(data []byte) (AppendEntriesResponse, error) {
	var resp AppendEntriesResponse
	err := json.Unmarshal(data, &resp)
	return resp, err
}
