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
	writeJSON(w, http.StatusOK, map[string]any{
		"whitelist": acl.WhitelistEntries(),
		"blacklist": acl.BlacklistEntries(),
	})
}

func (d *Dashboard) handleAddIPACL(w http.ResponseWriter, r *http.Request) {
	acl, ok := d.getIPACLLayer()
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "IP ACL layer not active"})
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
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ip is required"})
		return
	}

	var err error
	switch body.List {
	case "whitelist":
		err = acl.AddWhitelist(body.IP)
	case "blacklist":
		err = acl.AddBlacklist(body.IP)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "list must be 'whitelist' or 'blacklist'"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": sanitizeErr(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "ip": body.IP, "list": body.List})
}

func (d *Dashboard) handleRemoveIPACL(w http.ResponseWriter, r *http.Request) {
	acl, ok := d.getIPACLLayer()
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "IP ACL layer not active"})
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
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ip is required"})
		return
	}

	var err error
	switch body.List {
	case "whitelist":
		err = acl.RemoveWhitelist(body.IP)
	case "blacklist":
		err = acl.RemoveBlacklist(body.IP)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "list must be 'whitelist' or 'blacklist'"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": sanitizeErr(err)})
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
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "IP ACL layer not active"})
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
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ip is required"})
		return
	}
	ttl, err := time.ParseDuration(body.Duration)
	if err != nil || ttl <= 0 {
		ttl = 1 * time.Hour // default 1 hour
	}
	if body.Reason == "" {
		body.Reason = "manual ban from dashboard"
	}
	bl.AddAutoBan(body.IP, body.Reason, ttl)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "ip": body.IP, "duration": ttl.String()})
}

func (d *Dashboard) handleRemoveBan(w http.ResponseWriter, r *http.Request) {
	bl := d.getBanLayer()
	if bl == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "IP ACL layer not active"})
		return
	}
	var body struct {
		IP string `json:"ip"`
	}
	if !limitedDecodeJSON(w, r, &body) || body.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ip is required"})
		return
	}
	bl.RemoveAutoBan(body.IP)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "ip": body.IP})
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
