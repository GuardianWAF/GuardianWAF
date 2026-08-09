package dashboard

import (
	"net/http"
	"strings"
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
			d.handleClusterRedirect(w, r, err, body.IP, "ban")
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
			d.handleClusterRedirect(w, r, err, body.IP, "unban")
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

// handleClusterRedirect checks if a ProposeBan/ProposeUnban error means
// "this node is not the leader" and, if so, returns a 307 redirect response
// pointing the client at the leader's dashboard. If the leader is unknown or
// the error is something else, returns 503.
//
// The response body is JSON for programmatic clients; the Location header
// enables automatic redirect for HTTP clients and the dashboard frontend.
func (d *Dashboard) handleClusterRedirect(w http.ResponseWriter, r *http.Request, err error, ip, action string) {
	// Not a "not leader" error — return generic 503.
	if !d.clusterStatus.IsNotLeader(err) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":  err.Error(),
			"ip":     ip,
			"action": action,
		})
		return
	}

	leaderID := d.clusterStatus.LeaderID()
	leaderURL := ""

	// Look up the leader's dashboard URL from the peer list.
	for _, peer := range d.clusterStatus.Peers() {
		if peer.ID == leaderID && peer.DashboardURL != "" {
			leaderURL = peer.DashboardURL
			break
		}
	}

	// If the leader is self (shouldn't happen — we ARE the leader check),
	// or no leader URL is known, return a structured error.
	if leaderID == "" || leaderURL == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":     "not raft leader",
			"leader_id": leaderID,
			"ip":        ip,
			"action":    action,
			"hint":      "leader dashboard URL is not known; retry on the leader node directly",
		})
		return
	}

	// Build the redirect URL: same path + query on the leader's dashboard.
	location := strings.TrimRight(leaderURL, "/") + r.URL.Path
	if r.URL.RawQuery != "" {
		location += "?" + r.URL.RawQuery
	}

	w.Header().Set("Location", location)
	writeJSON(w, http.StatusTemporaryRedirect, map[string]any{
		"error":      "not raft leader",
		"leader_id":  leaderID,
		"leader_url": leaderURL,
		"location":   location,
		"ip":         ip,
		"action":     action,
		"hint":       "retry the request on the leader node",
	})
}
