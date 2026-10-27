package events

import (
	"encoding/json"
	"fmt"
	"github.com/guardianwaf/guardianwaf/internal/engine"
)

// unmarshalPersistedEvent accepts severity labels emitted by Event's JSON writer
// as well as the numeric severities used by older records.
func unmarshalPersistedEvent(data []byte, event *engine.Event) error {
	type eventFields engine.Event
	type findingFields engine.Finding
	var wire struct {
		eventFields
		Findings []struct {
			findingFields
			Severity json.RawMessage `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	decoded := engine.Event(wire.eventFields)
	if wire.Findings != nil {
		decoded.Findings = make([]engine.Finding, len(wire.Findings))
	}
	for i, entry := range wire.Findings {
		finding := engine.Finding(entry.findingFields)
		if len(entry.Severity) > 0 {
			if entry.Severity[0] == '"' {
				var label string
				if err := json.Unmarshal(entry.Severity, &label); err != nil {
					return err
				}
				found := false
				for severity := engine.SeverityInfo; severity <= engine.SeverityCritical; severity++ {
					if label == severity.String() {
						finding.Severity = severity
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("invalid persisted finding severity %q", label)
				}
			} else if err := json.Unmarshal(entry.Severity, &finding.Severity); err != nil {
				return err
			}
		}
		decoded.Findings[i] = finding
	}
	*event = decoded
	return nil
}
