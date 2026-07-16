package events

import "errors"

// errorWriter makes bufio.Writer flush fail; used by tests merged from events_extra_test.go
type errorWriter struct {
	n      int
	failAt int
}

func (e *errorWriter) Write(p []byte) (int, error) {
	if e.failAt >= 0 && e.n >= e.failAt {
		return 0, errors.New("write error")
	}
	e.n += len(p)
	return len(p), nil
}
