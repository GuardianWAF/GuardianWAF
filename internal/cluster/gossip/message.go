package gossip

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MessageType identifies the kind of gossip message.
type MessageType uint8

const (
	TypePing     MessageType = 1 // direct probe
	TypeAck      MessageType = 2 // probe response
	TypePingReq  MessageType = 3 // indirect probe (ask peer to probe)
	TypeAlive    MessageType = 4 // member is alive
	TypeSuspect  MessageType = 5 // member is suspected
	TypeDead     MessageType = 6 // member is dead
	TypePushPull MessageType = 7 // full state sync request/response
)

func (mt MessageType) String() string {
	switch mt {
	case TypePing:
		return "PING"
	case TypeAck:
		return "ACK"
	case TypePingReq:
		return "PING-REQ"
	case TypeAlive:
		return "ALIVE"
	case TypeSuspect:
		return "SUSPECT"
	case TypeDead:
		return "DEAD"
	case TypePushPull:
		return "PUSH-PULL"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", uint8(mt))
	}
}

// Message is a single gossip wire message.
//
// Wire format (binary, little-endian):
//
//	+--------+--------+--------+----------+-----------+----------+
//	| seq    | type   | srcLen | srcID    | payloadLen| payload  |
//	| uint32 | uint8  | uint8  | []byte   | uint16    | []byte   |
//	+--------+--------+--------+----------+-----------+----------+
//
// Piggybacked state updates are encoded inside the payload as a
// length-prefixed sequence of Member records (see EncodeMembers).
const (
	maxSourceIDLen  = 255
	maxPayloadLen   = 65535
	maxMembersInMsg = 64 // safety cap for piggybacked updates
	headerSize      = 8  // seq(4) + type(1) + srcLen(1) + payloadLen(2)
)

type Message struct {
	Seq     uint32
	Type    MessageType
	Source  string // sender node ID
	Payload []byte // type-specific data + piggybacked Member updates
}

// Encode serializes the message to the writer.
func (m *Message) Encode(w io.Writer) error {
	if len(m.Source) > maxSourceIDLen {
		return fmt.Errorf("source ID too long: %d bytes (max %d)", len(m.Source), maxSourceIDLen)
	}
	if len(m.Payload) > maxPayloadLen {
		return fmt.Errorf("payload too large: %d bytes (max %d)", len(m.Payload), maxPayloadLen)
	}

	// seq (4 bytes LE)
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:4], m.Seq)
	if _, err := w.Write(buf[:4]); err != nil {
		return fmt.Errorf("write seq: %w", err)
	}

	// type (1 byte)
	if _, err := w.Write([]byte{byte(m.Type)}); err != nil {
		return fmt.Errorf("write type: %w", err)
	}

	// srcLen (1 byte) — part of the fixed 8-byte header.
	if _, err := w.Write([]byte{byte(len(m.Source))}); err != nil {
		return fmt.Errorf("write srcLen: %w", err)
	}

	// payloadLen (2 bytes LE) — part of the fixed 8-byte header.
	binary.LittleEndian.PutUint16(buf[:2], uint16(len(m.Payload)))
	if _, err := w.Write(buf[:2]); err != nil {
		return fmt.Errorf("write payloadLen: %w", err)
	}

	// srcID (variable) — after the fixed header.
	if len(m.Source) > 0 {
		if _, err := w.Write([]byte(m.Source)); err != nil {
			return fmt.Errorf("write srcID: %w", err)
		}
	}

	// payload (variable) — after srcID.
	if len(m.Payload) > 0 {
		if _, err := w.Write(m.Payload); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}

	return nil
}

// DecodeMessage deserializes a message from the reader.
func DecodeMessage(r io.Reader) (*Message, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	msg := &Message{
		Seq:  binary.LittleEndian.Uint32(header[0:4]),
		Type: MessageType(header[4]),
	}

	srcLen := int(header[5])
	if srcLen > 0 {
		src := make([]byte, srcLen)
		if _, err := io.ReadFull(r, src); err != nil {
			return nil, fmt.Errorf("read srcID: %w", err)
		}
		msg.Source = string(src)
	}

	payloadLen := int(binary.LittleEndian.Uint16(header[6:8]))
	if payloadLen > 0 {
		msg.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, msg.Payload); err != nil {
			return nil, fmt.Errorf("read payload: %w", err)
		}
	}

	return msg, nil
}

// EncodeMessage returns the encoded bytes.
func (m *Message) EncodeMessage() ([]byte, error) {
	var buf []byte //nolint:prealloc // size varies
	w := byteWriter{buf: &buf}
	if err := m.Encode(&w); err != nil {
		return nil, err
	}
	return buf, nil
}

// DecodeMessageBytes decodes a message from a byte slice.
func DecodeMessageBytes(data []byte) (*Message, error) {
	return DecodeMessage(newBytesReader(data))
}

// --- Member encoding for piggybacked updates ---

// EncodeMembers encodes a list of members into a byte slice for piggybacking.
//
// Per-member format:
//
//	incarnation(8) + state(1) + idLen(1) + id + addrLen(1) + addr
func EncodeMembers(members []Member) []byte {
	var buf []byte
	for _, m := range members {
		if len(m.ID) > maxSourceIDLen {
			continue
		}
		// incarnation
		var tmp [8]byte
		binary.LittleEndian.PutUint64(tmp[:], m.Incarnation)
		buf = append(buf, tmp[:]...)
		// state
		buf = append(buf, byte(m.State))
		// idLen + id
		buf = append(buf, byte(len(m.ID)))
		buf = append(buf, m.ID...)
		// addrLen + addr
		buf = append(buf, byte(len(m.Addr)))
		buf = append(buf, m.Addr...)
	}
	return buf
}

// DecodeMembers decodes members from a piggyback payload.
func DecodeMembers(data []byte) ([]Member, error) {
	var members []Member
	offset := 0
	for offset < len(data) {
		if offset+10 > len(data) {
			return nil, fmt.Errorf("truncated member at offset %d", offset)
		}
		m := Member{
			Incarnation: binary.LittleEndian.Uint64(data[offset : offset+8]),
			State:       MemberState(data[offset+8]),
		}
		offset += 9

		idLen := int(data[offset])
		offset++
		if offset+idLen > len(data) {
			return nil, fmt.Errorf("truncated member ID")
		}
		m.ID = string(data[offset : offset+idLen])
		offset += idLen

		if offset >= len(data) {
			return nil, fmt.Errorf("truncated addr length")
		}
		addrLen := int(data[offset])
		offset++
		if offset+addrLen > len(data) {
			return nil, fmt.Errorf("truncated addr")
		}
		m.Addr = string(data[offset : offset+addrLen])
		offset += addrLen

		members = append(members, m)
	}
	return members, nil
}

// --- byte writer/reader adapters ---

type byteWriter struct {
	buf *[]byte
}

func (w *byteWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}

// bytesReader is a pointer-based reader that consumes a byte slice.
type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

func (b *bytesReader) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}
