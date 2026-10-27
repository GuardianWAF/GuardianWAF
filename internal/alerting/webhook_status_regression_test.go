package alerting

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

type batchF25Body struct {
	io.Reader
	closed bool
}

func (b *batchF25Body) Close() error { b.closed = true; return nil }

type batchF25Transport struct {
	status int
	body   *batchF25Body
}

func (s batchF25Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: s.status, Header: make(http.Header), Body: s.body, Request: r}, nil
}
func TestWebhookDeliveryRequiresSuccessfulFinalStatus(t *testing.T) {
	for _, status := range []int{199, 200, 201, 204, 299, 300, 302, 399, 400, 500} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			m := NewManager(nil)
			defer m.Close()
			body := &batchF25Body{Reader: strings.NewReader("response")}
			m.httpClient.Transport = batchF25Transport{status, body}
			err := m.send(&WebhookTarget{Name: "fixture", URL: "https://webhook.example/notify"}, &Alert{})
			success := status >= 200 && status < 300
			stats := m.GetStats()
			if (err == nil) != success || !body.closed {
				t.Fatalf("status %d err=%v closed=%v", status, err, body.closed)
			}
			if success {
				if stats.Sent != 1 || stats.Failed != 0 {
					t.Fatal(stats)
				}
			} else if stats.Sent != 0 || stats.Failed != 1 {
				t.Fatal(stats)
			}
		})
	}
	t.Log("FIX VERIFIED")
}
