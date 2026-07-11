package detection

import (
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

func TestLayerOrder(t *testing.T) {
	if got := NewLayer(&Config{}).Order(); got != engine.OrderDetection {
		t.Fatalf("Order() = %d, want %d", got, engine.OrderDetection)
	}
}
