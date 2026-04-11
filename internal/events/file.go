package events

import (
	"bufio"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

const (
	defaultMaxSize       = 100 * 1024 * 1024 // 100MB
	defaultMaxRotated    = 10                // Keep last 10 rotated files
	fileChannelBufSize   = 1024
	flushInterval        = time.Second
	flushEventCount      = 100
)

// FileStore writes events as JSONL (one JSON object per line) to a file.
type FileStore struct {
	mu       sync.Mutex
	file     *os.File
	writer   *bufio.Writer
	ch       chan engine.Event // buffered channel for async writes
	done     chan struct{}
	filePath string
	maxSize  int64 // max file size before rotation
	dropped  atomic.Int64 // count of dropped events
	closed   bool // guard against double-close of ch
}

// NewFileStore creates a new FileStore that writes JSONL to the specified file.
// maxSize controls file rotation threshold in bytes; 0 defaults to 100MB.
func NewFileStore(filePath string, maxSize int64) (*FileStore, error) {
	if maxSize <= 0 {
		maxSize = defaultMaxSize
	}

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}

	fs := &FileStore{
		file:     f,
		writer:   bufio.NewWriterSize(f, 32*1024),
		ch:       make(chan engine.Event, fileChannelBufSize),
		done:     make(chan struct{}),
		filePath: filePath,
		maxSize:  maxSize,
	}

	go fs.writeLoop()
	return fs, nil
}

// Store sends an event to the background writer. Non-blocking; drops the event if the channel is full.
func (fs *FileStore) Store(event engine.Event) error {
	select {
	case fs.ch <- event:
		return nil
	default:
		fs.dropped.Add(1)
		return errors.New("event dropped: file store channel full")
	}
}

// Query is not supported on FileStore.
func (fs *FileStore) Query(_ EventFilter) ([]engine.Event, int, error) {
	return nil, 0, errors.New("query not supported on file store")
}

// Get is not supported on FileStore.
func (fs *FileStore) Get(_ string) (*engine.Event, error) {
	return nil, errors.New("query not supported on file store")
}

// Recent is not supported on FileStore.
func (fs *FileStore) Recent(_ int) ([]engine.Event, error) {
	return nil, errors.New("query not supported on file store")
}

// Count is not supported on FileStore.
func (fs *FileStore) Count(_ EventFilter) (int, error) {
	return 0, errors.New("query not supported on file store")
}

// Dropped returns the number of events dropped due to a full channel.
func (fs *FileStore) Dropped() int64 {
	return fs.dropped.Load()
}

// Close stops the background writer, drains remaining events, flushes the buffer, and closes the file.
func (fs *FileStore) Close() error {
	fs.mu.Lock()
	if fs.closed {
		fs.mu.Unlock()
		return nil
	}
	fs.closed = true
	fs.mu.Unlock()

	close(fs.ch)
	<-fs.done // wait for writeLoop to finish

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if err := fs.writer.Flush(); err != nil {
		fs.file.Close()
		return err
	}
	_ = fs.file.Sync()
	return fs.file.Close()
}

// writeLoop is the background goroutine that reads events from the channel and writes them to the file.
func (fs *FileStore) writeLoop() {
	defer close(fs.done)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	eventsSinceFlush := 0

	for {
		select {
		case ev, ok := <-fs.ch:
			if !ok {
				// Channel closed — drain remaining events
				fs.drainRemaining()
				return
			}
			fs.writeEvent(ev)
			eventsSinceFlush++
			if eventsSinceFlush >= flushEventCount {
				fs.flush()
				eventsSinceFlush = 0
			}
		case <-ticker.C:
			if eventsSinceFlush > 0 {
				fs.flush()
				eventsSinceFlush = 0
			}
		}
	}
}

// drainRemaining reads and writes all remaining events from the channel after it has been closed.
func (fs *FileStore) drainRemaining() {
	for ev := range fs.ch {
		fs.writeEvent(ev)
	}
	fs.flush()
}

// writeEvent marshals and writes a single event as a JSON line.
func (fs *FileStore) writeEvent(ev engine.Event) {
	line := marshalEventJSON(ev)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	if _, err := fs.writer.WriteString(line); err != nil {
		return
	}
	if err := fs.writer.WriteByte('\n'); err != nil {
		return
	}

	// Check if rotation is needed
	fs.checkRotation()
}

// flush flushes the buffered writer to disk.
func (fs *FileStore) flush() {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.writer.Flush()
	// Sync to OS to reduce data loss window on crash.
	// Best-effort — ignore errors to avoid blocking the write loop.
	_ = fs.file.Sync()
}

// checkRotation checks if the file exceeds maxSize and rotates if necessary.
// Must be called with fs.mu held.
func (fs *FileStore) checkRotation() {
	// Flush buffered data so the on-disk size is accurate
	fs.writer.Flush()

	info, err := fs.file.Stat()
	if err != nil {
		return
	}
	if info.Size() < fs.maxSize {
		return
	}

	// Close current file before rename (required on Windows where open files cannot be renamed)
	oldFile := fs.file
	oldFile.Close()

	// Rename current file with timestamp
	ts := time.Now().Format("20060102-150405")
	ext := ""
	base := fs.filePath
	if idx := strings.LastIndex(fs.filePath, "."); idx >= 0 {
		ext = fs.filePath[idx:]
		base = fs.filePath[:idx]
	}
	rotatedName := base + "-" + ts + ext
	if renameErr := os.Rename(fs.filePath, rotatedName); renameErr != nil {
		// If rename fails, reopen the original file
		f, _ := os.OpenFile(fs.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if f != nil {
			fs.file = f
			fs.writer = bufio.NewWriterSize(f, 32*1024)
		}
		return
	}

	// Create new file
	f, err := os.OpenFile(fs.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		// If we can't create a new file, try to reopen with the rotated name
		f, _ = os.OpenFile(rotatedName, os.O_WRONLY|os.O_APPEND, 0o600)
	}
	if f != nil {
		fs.file = f
		fs.writer = bufio.NewWriterSize(f, 32*1024)
	} else {
		// Both attempts failed -- reopen original path as last resort
		f2, f2err := os.OpenFile(fs.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if f2err == nil {
			fs.file = f2
			fs.writer = bufio.NewWriterSize(f2, 32*1024)
		}
		// If even that fails, fs.file/fs.writer are stale but writes just fail silently
	}

	fs.cleanupRotated(base, ext)
}

// cleanupRotated removes old rotated files, keeping only the most recent ones.
// Must be called with fs.mu held.
func (fs *FileStore) cleanupRotated(base, ext string) {
	dir := "."
	// Use filepath.Separator for cross-platform compatibility
	if idx := strings.LastIndexAny(base, "/\\"); idx >= 0 {
		dir = base[:idx]
		base = base[idx+1:]
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	prefix := base + "-"
	var rotated []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), prefix) && strings.HasSuffix(e.Name(), ext) {
			rotated = append(rotated, e.Name())
		}
	}

	// Sort descending (newest first)
	sort.Sort(sort.Reverse(sort.StringSlice(rotated)))

	// Remove files beyond retention limit
	for i := defaultMaxRotated; i < len(rotated); i++ {
		_ = os.Remove(dir + string(os.PathSeparator) + rotated[i])
	}
}

// marshalEventJSON manually builds a JSON string for an Event without encoding/json.
func marshalEventJSON(ev engine.Event) string {
	var b strings.Builder
	b.Grow(512)

	b.WriteString(`{"id":`)
	writeJSONString(&b, ev.ID)
	b.WriteString(`,"timestamp":`)
	writeJSONString(&b, ev.Timestamp.Format(time.RFC3339Nano))
	b.WriteString(`,"request_id":`)
	writeJSONString(&b, ev.RequestID)
	b.WriteString(`,"client_ip":`)
	writeJSONString(&b, ev.ClientIP)
	b.WriteString(`,"method":`)
	writeJSONString(&b, ev.Method)
	b.WriteString(`,"path":`)
	writeJSONString(&b, ev.Path)
	b.WriteString(`,"query":`)
	writeJSONString(&b, ev.Query)
	b.WriteString(`,"action":`)
	writeJSONString(&b, ev.Action.String())
	b.WriteString(`,"score":`)
	writeJSONInt(&b, ev.Score)
	b.WriteString(`,"findings":[`)
	for i, f := range ev.Findings {
		if i > 0 {
			b.WriteByte(',')
		}
		marshalFinding(&b, f)
	}
	b.WriteString(`],"duration_ns":`)
	writeJSONInt64(&b, int64(ev.Duration))
	b.WriteString(`,"status_code":`)
	writeJSONInt(&b, ev.StatusCode)
	b.WriteString(`,"user_agent":`)
	writeJSONString(&b, ev.UserAgent)
	b.WriteString(`,"browser":`)
	writeJSONString(&b, ev.Browser)
	b.WriteString(`,"browser_version":`)
	writeJSONString(&b, ev.BrVersion)
	b.WriteString(`,"os":`)
	writeJSONString(&b, ev.OS)
	b.WriteString(`,"device_type":`)
	writeJSONString(&b, ev.DeviceType)
	b.WriteString(`,"is_bot":`)
	if ev.IsBot {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	b.WriteString(`,"content_type":`)
	writeJSONString(&b, ev.ContentType)
	b.WriteString(`,"referer":`)
	writeJSONString(&b, ev.Referer)
	b.WriteString(`,"host":`)
	writeJSONString(&b, ev.Host)
	b.WriteByte('}')

	return b.String()
}

// marshalFinding writes a Finding as JSON into the builder.
func marshalFinding(b *strings.Builder, f engine.Finding) {
	b.WriteString(`{"detector_name":`)
	writeJSONString(b, f.DetectorName)
	b.WriteString(`,"category":`)
	writeJSONString(b, f.Category)
	b.WriteString(`,"severity":`)
	writeJSONString(b, f.Severity.String())
	b.WriteString(`,"score":`)
	writeJSONInt(b, f.Score)
	b.WriteString(`,"description":`)
	writeJSONString(b, f.Description)
	b.WriteString(`,"matched_value":`)
	writeJSONString(b, f.MatchedValue)
	b.WriteString(`,"location":`)
	writeJSONString(b, f.Location)
	b.WriteString(`,"confidence":`)
	writeJSONFloat(b, f.Confidence)
	b.WriteByte('}')
}

// writeJSONString writes a properly escaped JSON string (with quotes) to the builder.
func writeJSONString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if c < 0x20 {
				// Other control characters: encode as \u00XX
				b.WriteString(`\u00`)
				b.WriteByte(hexDigit(c >> 4))
				b.WriteByte(hexDigit(c & 0x0f))
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
}

// hexDigit returns the hex digit character for a nibble value 0-15.
func hexDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + n - 10
}

// writeJSONInt writes an integer as a decimal string.
func writeJSONInt(b *strings.Builder, n int) {
	writeJSONInt64(b, int64(n))
}

// writeJSONInt64 writes an int64 as a decimal string.
func writeJSONInt64(b *strings.Builder, n int64) {
	if n == 0 {
		b.WriteByte('0')
		return
	}
	if n < 0 {
		b.WriteByte('-')
		n = -n
	}
	// Write digits in reverse, then reverse
	var digits [20]byte
	i := 0
	for n > 0 {
		digits[i] = byte(n%10) + '0'
		n /= 10
		i++
	}
	for i > 0 {
		i--
		b.WriteByte(digits[i])
	}
}

// writeJSONFloat writes a float64 with up to 6 decimal places.
func writeJSONFloat(b *strings.Builder, f float64) {
	if f < 0 {
		b.WriteByte('-')
		f = -f
	}

	intPart := int64(f)
	writeJSONInt64(b, intPart)

	frac := f - float64(intPart)
	if frac == 0 {
		return
	}

	b.WriteByte('.')
	// Up to 6 decimal places
	for range 6 {
		frac *= 10
		digit := int(frac)
		b.WriteByte(byte(digit) + '0')
		frac -= float64(digit)
		if frac < 1e-9 {
			break
		}
	}
}
