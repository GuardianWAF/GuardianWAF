package dashboard

import (
	"net/http"
	"time"
)

// --- IP ACL ---

// ipaclLayer is the interface we need from the ipacl layer (avoids circular import).
type ipaclLayer interface {
	AddWhitelist(cidr string) error
	RemoveWhitelist(cidr string) error
	AddBlacklist(cidr string) error
	RemoveBlacklist(cidr string) error
	WhitelistEntries() []string
	BlacklistEntries() []string
}

func (d *Dashboard) getIPACLLayer() (ipaclLayer, bool) {
	l := d.engine.FindLayer("ipacl")
	if l == nil {
		return nil, false
	}
	acl, ok := l.(ipaclLayer)
	return acl, ok
}

func (d *Dashboard) handleGetIPACL(w http.ResponseWriter, r *http.Request) {
	acl, ok := d.getIPACLLayer()
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"whitelist": []string{},
			"blacklist": []string{},
		})
		return
	}
	whitelist := acl.WhitelistEntries()
	if whitelist == nil {
		whitelist = []string{}
	}
	blacklist := acl.BlacklistEntries()
	if blacklist == nil {
		blacklist = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"whitelist": whitelist,
		"blacklist": blacklist,
	})
}

func (d *Dashboard) handleAddIPACL(w http.ResponseWriter, r *http.Request) {
	acl, ok := d.getIPACLLayer()
	if !ok {
		writeError(w, http.StatusBadRequest, "IP ACL layer not active")
		return
	}

	var body struct {
		List string `json:"list"` // "whitelist" or "blacklist"
		IP   string `json:"ip"`
	}
	if !limitedDecodeJSON(w, r, &body) {
		return
	}
	if body.IP == "" {
		writeError(w, http.StatusBadRequest, "ip is required")
		return
	}

	var err error
	switch body.List {
	case "whitelist":
		err = acl.AddWhitelist(body.IP)
	case "blacklist":
		err = acl.AddBlacklist(body.IP)
	default:
		writeError(w, http.StatusBadRequest, "list must be 'whitelist' or 'blacklist'")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, sanitizeErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "ip": body.IP, "list": body.List})
}

func (d *Dashboard) handleRemoveIPACL(w http.ResponseWriter, r *http.Request) {
	acl, ok := d.getIPACLLayer()
	if !ok {
		writeError(w, http.StatusBadRequest, "IP ACL layer not active")
		return
	}

	var body struct {
		List string `json:"list"`
		IP   string `json:"ip"`
	}
	if !limitedDecodeJSON(w, r, &body) {
		return
	}
	if body.IP == "" {
		writeError(w, http.StatusBadRequest, "ip is required")
		return
	}

	var err error
	switch body.List {
	case "whitelist":
		err = acl.RemoveWhitelist(body.IP)
	case "blacklist":
		err = acl.RemoveBlacklist(body.IP)
	default:
		writeError(w, http.StatusBadRequest, "list must be 'whitelist' or 'blacklist'")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, sanitizeErr(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "ip": body.IP, "list": body.List})
}

// --- Temporary Bans ---

// banLayer is the interface for temp ban operations (avoids circular import).
type banLayer interface {
	AddAutoBan(ip string, reason string, ttl time.Duration)
	RemoveAutoBan(ip string)
}

func (d *Dashboard) handleGetBans(w http.ResponseWriter, r *http.Request) {
	bl := d.getBanLayer()
	if bl == nil {
		writeJSON(w, http.StatusOK, map[string]any{"bans": []any{}})
		return
	}
	type banLister interface{ ActiveBansAny() any }
	if lister, ok := bl.(banLister); ok {
		writeJSON(w, http.StatusOK, map[string]any{"bans": lister.ActiveBansAny()})
	} else {
		writeJSON(w, http.StatusOK, map[string]any{"bans": []any{}})
	}
}

func (d *Dashboard) handleAddBan(w http.ResponseWriter, r *http.Request) {
	bl := d.getBanLayer()
	if bl == nil {
		writeError(w, http.StatusBadRequest, "IP ACL layer not active")
		return
	}
	var body struct {
		IP       string `json:"ip"`
		Reason   string `json:"reason"`
		Duration string `json:"duration"` // e.g. "30m", "1h", "24h"
	}
	if !limitedDecodeJSON(w, r, &body) {
		return
	}
	if body.IP == "" {
		writeError(w, http.StatusBadRequest, "ip is required")
		return
	}
	ttl, err := time.ParseDuration(body.Duration)
	if err != nil || ttl <= 0 {
		ttl = 1 * time.Hour // default 1 hour
	}
	if body.Reason == "" {
		body.Reason = "manual ban from dashboard"
	}

	// When cluster mode is active, propose the ban via Raft so it replicates
	// to all nodes. Also apply locally for immediate enforcement on this node.
	if d.clusterStatus != nil {
		if err := d.clusterStatus.ProposeBan(body.IP, ttl); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status": "error",
				"ip":     body.IP,
				"error":  err.Error(),
				"hint":   "ban proposal requires the Raft leader; redirect to the leader node",
			})
			return
		}
	}

	// Apply locally (immediate effect on this node; other nodes get it via Raft).
	bl.AddAutoBan(body.IP, body.Reason, ttl)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"ip":       body.IP,
		"duration": ttl.String(),
		"cluster":  d.clusterStatus != nil,
	})
}

func (d *Dashboard) handleRemoveBan(w http.ResponseWriter, r *http.Request) {
	bl := d.getBanLayer()
	if bl == nil {
		writeError(w, http.StatusBadRequest, "IP ACL layer not active")
		return
	}
	var body struct {
		IP string `json:"ip"`
	}
	if !limitedDecodeJSON(w, r, &body) || body.IP == "" {
		writeError(w, http.StatusBadRequest, "ip is required")
		return
	}

	// When cluster mode is active, propose the unban via Raft so it replicates.
	if d.clusterStatus != nil {
		if err := d.clusterStatus.ProposeUnban(body.IP); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status": "error",
				"ip":     body.IP,
				"error":  err.Error(),
				"hint":   "unban proposal requires the Raft leader; redirect to the leader node",
			})
			return
		}
	}

	// Apply locally (immediate effect on this node; other nodes get it via Raft).
	bl.RemoveAutoBan(body.IP)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "ip": body.IP, "cluster": d.clusterStatus != nil})
}

func (d *Dashboard) getBanLayer() banLayer {
	l := d.engine.FindLayer("ipacl")
	if l == nil {
		return nil
	}
	bl, ok := l.(banLayer)
	if !ok {
		return nil
	}
	return bl
}
