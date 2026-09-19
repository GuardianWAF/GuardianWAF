package websocket

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// Regression (round 2026-09-18): ReadFrame silently tolerated RFC 6455 §5.1
// direction violations in BOTH directions — the masked reader (client leg)
// accepted MASK=0 client frames although the server MUST close on them, and
// the unmasked reader (backend leg) accepted MASK=1 backend frames although
// the client MUST close on them. The tolerance once let a relay masking bug
// (frames written unmasked toward the backend) pass the package's own tests.
// Direction violations are now ErrMaskViolation; the relay refuses them with
// a 1002 protocol-error close and tears both legs down.

func TestReadFrameRejectsWrongDirectionMask(t *testing.T) {
	// MASK=0 client frame on the masked (client→server) reader: MUST reject.
	_, err := NewMaskedFrameReader(bytes.NewReader([]byte{0x81, 0x02, 'h', 'i'}), 1<<20).ReadFrame()
	if err == nil {
		t.Fatalf("MASK=0 client frame accepted — RFC 6455 §5.1 requires the server to close")
	}
	if !errors.Is(err, ErrMaskViolation) {
		t.Fatalf("MASK=0 client frame: err = %v, want ErrMaskViolation", err)
	}

	// MASK=1 backend frame on the unmasked (server→client) reader: MUST reject.
	masked := []byte{0x81, 0x82, 1, 2, 3, 4, 'x', 'y'}
	_, err = NewFrameReader(bytes.NewReader(masked), 1<<20).ReadFrame()
	if err == nil {
		t.Fatalf("MASK=1 backend frame accepted — RFC 6455 §5.1 requires the client to close")
	}
	if !errors.Is(err, ErrMaskViolation) {
		t.Fatalf("MASK=1 backend frame: err = %v, want ErrMaskViolation", err)
	}

	// Direction-compliant frames keep parsing.
	if _, err := NewMaskedFrameReader(bytes.NewReader(masked), 1<<20).ReadFrame(); err != nil {
		t.Fatalf("compliant MASK=1 client frame rejected: %v", err)
	}
	if _, err := NewFrameReader(bytes.NewReader([]byte{0x81, 0x02, 'h', 'i'}), 1<<20).ReadFrame(); err != nil {
		t.Fatalf("compliant MASK=0 server frame rejected: %v", err)
	}
}

// End-to-end through the relay: an unmasked client frame is refused with a
// 1002 protocol-error close toward the backend, and BOTH legs are torn down
// (no zombie relay, no held resources).
//
// Harness note: net.Pipe is synchronous and the relay consumes only the
// 2-byte header before refusing (the violation is detected at the mask bit),
// so neither side's I/O completes without the other being drained — the
// refusal is read concurrently with the probe write, and net.Pipe deadlines
// bound every wait. The probe write unblocks via the teardown close of the
// client leg mid-frame: its error is itself teardown evidence.
func TestRelayRefusesMaskViolationWith1002AndTeardown(t *testing.T) {
	clientA, clientB := net.Pipe() // client leg: test ⇄ relay
	backendR, backendW := net.Pipe()
	defer backendR.Close()

	deadline := time.Now().Add(10 * time.Second)
	if err := backendR.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := clientA.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	// Drain everything the relay writes toward the backend until the refusal
	// is complete and the leg is torn down (Read errors after teardownConns
	// closes backendW).
	refusal := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		p := make([]byte, 256)
		for {
			n, err := backendR.Read(p)
			if n > 0 {
				buf.Write(p[:n])
			}
			if err != nil {
				break
			}
		}
		refusal <- buf.Bytes()
	}()

	go func() {
		l := NewLayer(&Config{
			Enabled:      true,
			ScanPayloads: true,
		})
		l.inspectAndForward(clientB, backendW, "1.2.3.4", "/ws", true)
	}()

	// One unmasked client text frame — a §5.1 MUST violation. The relay
	// consumes the header, refuses, and tears the client leg down mid-frame:
	// the write must error (a clean completion would mean the violating frame
	// was accepted and relayed).
	if _, err := clientA.Write([]byte{0x81, 0x02, 'h', 'i'}); err == nil {
		t.Fatalf("probe write completed — the violating frame was not refused at the header")
	}

	chunk := <-refusal
	if len(chunk) == 0 {
		t.Fatalf("no refusal close read from the backend leg")
	}
	v := parseFirstWireFrame(t, chunk)
	if v.opcode != OpClose {
		t.Fatalf("opcode = %v, want OpClose (refusal)", v.opcode)
	}
	dec := unmaskView(t, v)
	if len(dec) < 2 || int(dec[0])<<8|int(dec[1]) != 1002 {
		t.Fatalf("close code = %v, want 1002", dec)
	}
}
