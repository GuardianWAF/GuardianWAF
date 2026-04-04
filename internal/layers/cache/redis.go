package cache

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RedisBackend provides a Redis-compatible cache backend.
// This uses Go's standard net package (zero external dependencies).
type RedisBackend struct {
	addr     string
	password string
	db       int
	conn     net.Conn
	mu       sync.Mutex
	reader   *bufio.Reader
	writer   *bufio.Writer
}

// NewRedisBackend creates a new Redis backend.
func NewRedisBackend(addr, password string, db int) (*RedisBackend, error) {
	if addr == "" {
		addr = "localhost:6379"
	}

	rb := &RedisBackend{
		addr:     addr,
		password: password,
		db:       db,
	}

	// Connect
	if err := rb.connect(); err != nil {
		return nil, err
	}

	return rb, nil
}

// connect establishes connection to Redis.
func (rb *RedisBackend) connect() error {
	conn, err := net.DialTimeout("tcp", rb.addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}

	rb.conn = conn
	rb.reader = bufio.NewReader(conn)
	rb.writer = bufio.NewWriter(conn)

	// Authenticate if password provided
	if rb.password != "" {
		if err := rb.auth(rb.password); err != nil {
			conn.Close()
			return err
		}
	}

	// Select database
	if err := rb.selectDB(rb.db); err != nil {
		conn.Close()
		return err
	}

	return nil
}

// auth sends AUTH command.
func (rb *RedisBackend) auth(password string) error {
	return rb.sendCommand("AUTH", password)
}

// selectDB sends SELECT command.
func (rb *RedisBackend) selectDB(db int) error {
	return rb.sendCommand("SELECT", strconv.Itoa(db))
}

// sendCommand sends a Redis command.
func (rb *RedisBackend) sendCommand(args ...string) error {
	// Build RESP command
	cmd := fmt.Sprintf("*%d\r\n", len(args))
	for _, arg := range args {
		cmd += fmt.Sprintf("$%d\r\n%s\r\n", len(arg), arg)
	}

	if _, err := rb.writer.WriteString(cmd); err != nil {
		return err
	}
	return rb.writer.Flush()
}

// readResponse reads a Redis response.
func (rb *RedisBackend) readResponse() ([]byte, error) {
	line, err := rb.reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	if len(line) == 0 {
		return nil, fmt.Errorf("empty response")
	}

	prefix := line[0]
	data := strings.TrimSpace(line[1:])

	switch prefix {
	case '+': // Simple string
		return []byte(data), nil
	case '-': // Error
		return nil, fmt.Errorf("redis error: %s", data)
	case ':': // Integer
		return []byte(data), nil
	case '$': // Bulk string
		size, err := strconv.Atoi(data)
		if err != nil {
			return nil, err
		}
		if size == -1 {
			return nil, nil // nil bulk string
		}
		buf := make([]byte, size+2) // +2 for \r\n
		_, err = io.ReadFull(rb.reader, buf)
		if err != nil {
			return nil, err
		}
		return buf[:size], nil
	case '*': // Array
		return []byte(data), nil // Simplified, not fully implemented
	default:
		return nil, fmt.Errorf("unknown response type: %c", prefix)
	}
}

// Get retrieves a value from Redis.
func (rb *RedisBackend) Get(ctx context.Context, key string) ([]byte, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if err := rb.sendCommand("GET", key); err != nil {
		return nil, err
	}

	return rb.readResponse()
}

// Set stores a value in Redis.
func (rb *RedisBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if ttl > 0 {
		seconds := int(ttl.Seconds())
		return rb.sendCommand("SETEX", key, strconv.Itoa(seconds), string(value))
	}
	return rb.sendCommand("SET", key, string(value))
}

// Delete removes a key from Redis.
func (rb *RedisBackend) Delete(ctx context.Context, key string) error {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	return rb.sendCommand("DEL", key)
}

// Exists checks if a key exists in Redis.
func (rb *RedisBackend) Exists(ctx context.Context, key string) (bool, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if err := rb.sendCommand("EXISTS", key); err != nil {
		return false, err
	}

	resp, err := rb.readResponse()
	if err != nil {
		return false, err
	}

	count, _ := strconv.Atoi(string(resp))
	return count > 0, nil
}

// Keys returns keys matching pattern.
func (rb *RedisBackend) Keys(ctx context.Context, pattern string) ([]string, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if err := rb.sendCommand("KEYS", pattern); err != nil {
		return nil, err
	}

	// Simplified implementation - returns empty
	return []string{}, nil
}

// Clear removes all keys (uses FLUSHDB).
func (rb *RedisBackend) Clear(ctx context.Context) error {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	return rb.sendCommand("FLUSHDB")
}

// Close closes the Redis connection.
func (rb *RedisBackend) Close() error {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.conn != nil {
		return rb.conn.Close()
	}
	return nil
}
