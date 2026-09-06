package clustersync

import (
	"encoding/json"
	"fmt"
	"time"
)

// CmdType identifies a replicated command in the Raft log.
type CmdType uint8

const (
	CmdBanIP        CmdType = 1 // { ip, duration }
	CmdUnbanIP      CmdType = 2 // { ip }
	CmdSetRule      CmdType = 3 // { rule_id, rule }
	CmdDeleteRule   CmdType = 4 // { rule_id }
	CmdIncrCounter  CmdType = 5 // { key, delta, window }
	CmdResetCounter CmdType = 6 // { key }
)

// String returns a human-readable name for the command type.
func (c CmdType) String() string {
	switch c {
	case CmdBanIP:
		return "BanIP"
	case CmdUnbanIP:
		return "UnbanIP"
	case CmdSetRule:
		return "SetRule"
	case CmdDeleteRule:
		return "DeleteRule"
	case CmdIncrCounter:
		return "IncrCounter"
	case CmdResetCounter:
		return "ResetCounter"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(c)) // #nosec G115 -- uint8→uint8 safe
	}
}

// Command is the envelope for all replicated mutations. It is JSON-encoded
// into the Raft LogEntry.Command field.
type Command struct {
	Type    CmdType         `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// --- Payload types ---

type BanIPPayload struct {
	IP       string        `json:"ip"`
	Duration time.Duration `json:"duration"` // 0 = permanent
}

type UnbanIPPayload struct {
	IP string `json:"ip"`
}

type SetRulePayload struct {
	RuleID string          `json:"rule_id"`
	Rule   json.RawMessage `json:"rule"`
}

type DeleteRulePayload struct {
	RuleID string `json:"rule_id"`
}

type IncrCounterPayload struct {
	Key    string `json:"key"`
	Delta  int64  `json:"delta"`
	Window int64  `json:"window"` // epoch window (e.g., Unix seconds / 60)
}

type ResetCounterPayload struct {
	Key string `json:"key"`
}

// Encode serializes a Command into JSON bytes suitable for Raft Propose().
func (c Command) Encode() ([]byte, error) {
	return json.Marshal(c)
}

// DecodeCommand deserializes a Command from JSON bytes (from a Raft LogEntry).
func DecodeCommand(data []byte) (Command, error) {
	var cmd Command
	if err := json.Unmarshal(data, &cmd); err != nil {
		return Command{}, fmt.Errorf("clustersync: decode command: %w", err)
	}
	return cmd, nil
}

// NewBanCommand creates a ban command. Duration 0 means permanent; negative
// durations are rejected — applyBanIP only sets ExpiresAt for positive
// durations, so a negative request would silently escalate to a permanent ban.
func NewBanCommand(ip string, duration time.Duration) (Command, error) {
	if duration < 0 {
		return Command{}, fmt.Errorf("clustersync: invalid ban duration %s (0 = permanent)", duration)
	}
	payload, err := json.Marshal(BanIPPayload{IP: ip, Duration: duration})
	if err != nil {
		return Command{}, err
	}
	return Command{Type: CmdBanIP, Payload: payload}, nil
}

// NewUnbanCommand creates an unban command.
func NewUnbanCommand(ip string) (Command, error) {
	payload, err := json.Marshal(UnbanIPPayload{IP: ip})
	if err != nil {
		return Command{}, err
	}
	return Command{Type: CmdUnbanIP, Payload: payload}, nil
}

// NewSetRuleCommand creates a set-rule command.
func NewSetRuleCommand(ruleID string, rule json.RawMessage) (Command, error) {
	payload, err := json.Marshal(SetRulePayload{RuleID: ruleID, Rule: rule})
	if err != nil {
		return Command{}, err
	}
	return Command{Type: CmdSetRule, Payload: payload}, nil
}

// NewDeleteRuleCommand creates a delete-rule command.
func NewDeleteRuleCommand(ruleID string) (Command, error) {
	payload, err := json.Marshal(DeleteRulePayload{RuleID: ruleID})
	if err != nil {
		return Command{}, err
	}
	return Command{Type: CmdDeleteRule, Payload: payload}, nil
}

// NewIncrCounterCommand creates an increment-counter command.
func NewIncrCounterCommand(key string, delta int64, window int64) (Command, error) {
	payload, err := json.Marshal(IncrCounterPayload{Key: key, Delta: delta, Window: window})
	if err != nil {
		return Command{}, err
	}
	return Command{Type: CmdIncrCounter, Payload: payload}, nil
}

// NewResetCounterCommand creates a reset-counter command.
func NewResetCounterCommand(key string) (Command, error) {
	payload, err := json.Marshal(ResetCounterPayload{Key: key})
	if err != nil {
		return Command{}, err
	}
	return Command{Type: CmdResetCounter, Payload: payload}, nil
}

// DecodePayload unmarshals the command payload into the provided target.
// The caller is responsible for passing a pointer to the correct payload
// type for this command's Type.
func (c Command) DecodePayload(target any) error {
	return json.Unmarshal(c.Payload, target)
}
