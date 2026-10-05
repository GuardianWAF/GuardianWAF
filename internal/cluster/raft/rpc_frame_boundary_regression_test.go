package raft

import (
	"bytes"
	"testing"
)

func TestRPCFrameLengthBoundary(t *testing.T) {
	for _, size := range []int{0, 1, maxFrameSize - 1, maxFrameSize, maxFrameSize + 1} {
		var out bytes.Buffer
		payload := make([]byte, size)
		if size > 0 {
			payload[size-1] = 7
		}
		err := EncodeRequest(&out, RPCRequestVoteRequest, payload)
		if size > maxFrameSize {
			if err == nil || out.Len() != 0 {
				t.Fatalf("size=%d err=%v written=%d", size, err, out.Len())
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		typ, got, err := ReadFrame(&out)
		if err != nil || typ != RPCRequestVoteRequest || !bytes.Equal(got, payload) {
			t.Fatalf("size=%d type=%d err=%v", size, typ, err)
		}
	}
}
