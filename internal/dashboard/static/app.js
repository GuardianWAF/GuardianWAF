// =========================================================================
// GuardianWAF Dashboard — Vanilla JS Application
// =========================================================================
//
// All dynamic HTML insertion uses escapeHtml() to prevent XSS.
// innerHTML is used only with pre-escaped content for rendering charts
// and badges where DOM creation would be excessively verbose.
//

(function () {
    'use strict';

    // --- Configuration ---
    var API_BASE = '';
    var SSE_URL = API_BASE + '/api/v1/sse';
    var STATS_URL = API_BASE + '/api/v1/stats';
    var EVENTS_URL = API_BASE + '/api/v1/events';
    var STATS_POLL_INTERVAL = 5000;
    var MAX_EVENTS = 200;

    // --- State ---
    var state = {
        events: [],
        stats: {
            total_requests: 0,
            blocked: 0,
            logged: 0,
            passed: 0,
            avg_latency_ms: 0,
            p99_latency_ms: 0,
            requests_per_second: 0,
            attack_types: {},
            top_ips: []
        },
        activeFilter: 'all',
        searchQuery: '',
        sseRetryDelay: 1000,
        sseMaxRetryDelay: 30000
    };

    // --- DOM References ---
    var dom = {};

    function cacheDom() {
        dom.statTotal = document.getElementById('stat-total');
        dom.statBlocked = document.getElementById('stat-blocked');
        dom.statLogged = document.getElementById('stat-logged');
        dom.statPassed = document.getElementById('stat-passed');
        dom.statLatency = document.getElementById('stat-latency');
        dom.statTotalRate = document.getElementById('stat-total-rate');
        dom.statBlockedPct = document.getElementById('stat-blocked-pct');
        dom.statLoggedPct = document.getElementById('stat-logged-pct');
        dom.statPassedPct = document.getElementById('stat-passed-pct');
        dom.statLatencyP99 = document.getElementById('stat-latency-p99');
        dom.eventsTbody = document.getElementById('events-tbody');
        dom.eventsFeed = document.getElementById('events-feed');
        dom.eventsCount = document.getElementById('events-count');
        dom.eventsFiltered = document.getElementById('events-filtered');
        dom.searchInput = document.getElementById('search-input');
        dom.sseStatus = document.getElementById('sse-status');
        dom.sseStatusLabel = document.getElementById('sse-status-label');
        dom.chartAttackTypes = document.getElementById('chart-attack-types');
        dom.chartTopIps = document.getElementById('chart-top-ips');
        dom.footerVersion = document.getElementById('footer-version');
    }

    // =========================================================================
    // Helper Functions
    // =========================================================================

    /**
     * Format a number with compact notation (1.2k, 3.4M).
     */
    function formatNumber(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
        return String(n);
    }

    /**
     * Format duration in milliseconds to a human-readable string.
     */
    function formatDuration(ms) {
        if (ms < 1) return '<1ms';
        if (ms < 1000) return Math.round(ms) + 'ms';
        if (ms < 60000) return (ms / 1000).toFixed(1) + 's';
        return (ms / 60000).toFixed(1) + 'm';
    }

    /**
     * Format a timestamp (ISO string or Unix ms) as relative time.
     */
    function formatTimestamp(ts) {
        var date;
        if (typeof ts === 'number') {
            date = new Date(ts);
        } else {
            date = new Date(ts);
        }
        var now = Date.now();
        var diff = now - date.getTime();

        if (diff < 0) return 'just now';
        if (diff < 5000) return 'just now';
        if (diff < 60000) return Math.floor(diff / 1000) + 's ago';
        if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
        if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
        return Math.floor(diff / 86400000) + 'd ago';
    }

    /**
     * Escape HTML special characters to prevent XSS.
     * This is critical — all user-controlled strings must pass through here
     * before being placed into HTML.
     */
    function escapeHtml(str) {
        if (!str) return '';
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    /**
     * Return an HTML badge span for an action type.
     * Action values are constrained to "blocked"/"logged"/"passed" from
     * the server, and are escaped regardless.
     */
    function actionBadge(action) {
        var cls = 'badge badge--passed';
        var label = action || 'passed';
        if (action === 'block') cls = 'badge badge--blocked';
        else if (action === 'log') cls = 'badge badge--logged';
        return '<span class="' + cls + '">' + escapeHtml(label) + '</span>';
    }

    /**
     * Return a device type badge.
     */
    function deviceBadge(device) {
        return '<span class="badge badge--device">' + escapeHtml(device || 'unknown') + '</span>';
    }

    /**
     * Get CSS class for a score value.
     */
    function scoreClass(score) {
        if (score >= 50) return 'score-high';
        if (score >= 25) return 'score-medium';
        return 'score-low';
    }

    /**
     * Truncate a string to maxLen characters.
     */
    function truncate(str, maxLen) {
        if (!str) return '';
        if (str.length <= maxLen) return str;
        return str.substring(0, maxLen) + '\u2026';
    }

    /**
     * Calculate percentage, return "0%" if total is 0.
     */
    function pct(value, total) {
        if (!total) return '0%';
        return ((value / total) * 100).toFixed(1) + '%';
    }

    // =========================================================================
    // Stats Rendering
    // =========================================================================

    function renderStats() {
        var s = state.stats;
        dom.statTotal.textContent = formatNumber(s.total_requests);
        dom.statBlocked.textContent = formatNumber(s.blocked);
        dom.statLogged.textContent = formatNumber(s.logged);
        dom.statPassed.textContent = formatNumber(s.passed);
        dom.statLatency.textContent = formatDuration(s.avg_latency_ms);

        dom.statTotalRate.textContent = (s.requests_per_second || 0).toFixed(1) + ' req/s';
        dom.statBlockedPct.textContent = pct(s.blocked, s.total_requests);
        dom.statLoggedPct.textContent = pct(s.logged, s.total_requests);
        dom.statPassedPct.textContent = pct(s.passed, s.total_requests);
        dom.statLatencyP99.textContent = 'P99: ' + formatDuration(s.p99_latency_ms || 0);
    }

    // =========================================================================
    // Attack Types Bar Chart (CSS-only, no libraries)
    // =========================================================================

    var ATTACK_COLORS = {
        sqli: 'sqli',
        xss: 'xss',
        lfi: 'lfi',
        cmdi: 'cmdi',
        xxe: 'xxe',
        ssrf: 'ssrf',
        bot: 'bot'
    };

    function renderAttackTypes() {
        var types = state.stats.attack_types;
        if (!types || Object.keys(types).length === 0) {
            dom.chartAttackTypes.textContent = '';
            var empty = document.createElement('div');
            empty.className = 'chart-empty';
            empty.textContent = 'No attack data yet';
            dom.chartAttackTypes.appendChild(empty);
            return;
        }

        // Find max for scaling
        var maxVal = 0;
        var entries = [];
        for (var key in types) {
            if (types.hasOwnProperty(key)) {
                entries.push({ name: key, count: types[key] });
                if (types[key] > maxVal) maxVal = types[key];
            }
        }

        // Sort descending
        entries.sort(function (a, b) { return b.count - a.count; });

        // Build chart via DOM methods
        var chart = document.createElement('div');
        chart.className = 'bar-chart';

        for (var i = 0; i < entries.length; i++) {
            var e = entries[i];
            var widthPct = maxVal > 0 ? ((e.count / maxVal) * 100) : 0;
            var colorClass = ATTACK_COLORS[e.name] || 'default';

            var row = document.createElement('div');
            row.className = 'bar-row';

            var label = document.createElement('span');
            label.className = 'bar-label';
            label.textContent = e.name;
            row.appendChild(label);

            var track = document.createElement('div');
            track.className = 'bar-track';
            var fill = document.createElement('div');
            fill.className = 'bar-fill bar-fill--' + colorClass;
            fill.style.width = widthPct + '%';
            track.appendChild(fill);
            row.appendChild(track);

            var count = document.createElement('span');
            count.className = 'bar-count';
            count.textContent = formatNumber(e.count);
            row.appendChild(count);

            chart.appendChild(row);
        }

        dom.chartAttackTypes.textContent = '';
        dom.chartAttackTypes.appendChild(chart);
    }

    // =========================================================================
    // Top IPs List
    // =========================================================================

    function renderTopIps() {
        var ips = state.stats.top_ips;
        if (!ips || ips.length === 0) {
            dom.chartTopIps.textContent = '';
            var empty = document.createElement('div');
            empty.className = 'chart-empty';
            empty.textContent = 'No IP data yet';
            dom.chartTopIps.appendChild(empty);
            return;
        }

        var list = document.createElement('div');
        list.className = 'top-ips-list';

        var limit = Math.min(ips.length, 10);
        for (var i = 0; i < limit; i++) {
            var entry = ips[i];
            var ip = entry.ip || entry.IP || '';
            var cnt = entry.count || entry.Count || 0;

            var row = document.createElement('div');
            row.className = 'top-ip-row';

            var rank = document.createElement('span');
            rank.className = 'top-ip-rank';
            rank.textContent = String(i + 1);
            row.appendChild(rank);

            var addr = document.createElement('span');
            addr.className = 'top-ip-addr';
            addr.textContent = ip;
            row.appendChild(addr);

            var countEl = document.createElement('span');
            countEl.className = 'top-ip-count';
            countEl.textContent = formatNumber(cnt);
            row.appendChild(countEl);

            list.appendChild(row);
        }

        dom.chartTopIps.textContent = '';
        dom.chartTopIps.appendChild(list);
    }

    // =========================================================================
    // Event Feed Rendering
    // =========================================================================

    function matchesFilter(event) {
        // Action filter
        if (state.activeFilter !== 'all' && event.action !== state.activeFilter) {
            return false;
        }
        // Search filter
        if (state.searchQuery) {
            var q = state.searchQuery.toLowerCase();
            var haystack = [
                event.client_ip || '',
                event.method || '',
                event.path || '',
                event.action || '',
                event.browser || '',
                event.os || '',
                event.device || ''
            ].join(' ').toLowerCase();
            if (haystack.indexOf(q) === -1) return false;
        }
        return true;
    }

    function createEventRow(event, isNew) {
        var tr = document.createElement('tr');
        if (isNew) tr.className = 'event-new';

        // Timestamp
        var tdTime = document.createElement('td');
        tdTime.textContent = formatTimestamp(event.timestamp);
        tdTime.title = event.timestamp ? new Date(event.timestamp).toLocaleString() : '';
        tr.appendChild(tdTime);

        // IP
        var tdIp = document.createElement('td');
        tdIp.className = 'td-ip';
        tdIp.textContent = event.client_ip || '-';
        tr.appendChild(tdIp);

        // Method
        var tdMethod = document.createElement('td');
        tdMethod.className = 'td-method';
        tdMethod.textContent = event.method || '-';
        tr.appendChild(tdMethod);

        // Path
        var tdPath = document.createElement('td');
        tdPath.className = 'td-path';
        tdPath.textContent = truncate(event.path || '-', 50);
        tdPath.title = event.path || '';
        tr.appendChild(tdPath);

        // Action badge — uses escaped content via actionBadge()
        var tdAction = document.createElement('td');
        var actionSpan = document.createElement('span');
        var actionVal = event.action || 'pass';
        actionSpan.className = 'badge badge--passed';
        if (actionVal === 'block') { actionSpan.className = 'badge badge--blocked'; actionSpan.textContent = 'BLOCKED'; }
        else if (actionVal === 'log') { actionSpan.className = 'badge badge--logged'; actionSpan.textContent = 'LOGGED'; }
        else { actionSpan.textContent = 'PASSED'; }
        tdAction.appendChild(actionSpan);
        tr.appendChild(tdAction);

        // Score
        var tdScore = document.createElement('td');
        tdScore.className = 'td-score ' + scoreClass(event.score || 0);
        tdScore.textContent = event.score != null ? event.score : '-';
        tr.appendChild(tdScore);

        // Browser
        var tdBrowser = document.createElement('td');
        tdBrowser.textContent = truncate(event.browser || '-', 15);
        tr.appendChild(tdBrowser);

        // OS
        var tdOS = document.createElement('td');
        tdOS.textContent = truncate(event.os || '-', 12);
        tr.appendChild(tdOS);

        // Device
        var tdDevice = document.createElement('td');
        var deviceSpan = document.createElement('span');
        deviceSpan.className = 'badge badge--device';
        deviceSpan.textContent = event.device || 'unknown';
        tdDevice.appendChild(deviceSpan);
        tr.appendChild(tdDevice);

        return tr;
    }

    function renderEvents() {
        var tbody = dom.eventsTbody;
        // Clear all children safely
        while (tbody.firstChild) {
            tbody.removeChild(tbody.firstChild);
        }

        var filtered = state.events.filter(matchesFilter);

        if (filtered.length === 0) {
            var tr = document.createElement('tr');
            tr.className = 'events-empty-row';
            var td = document.createElement('td');
            td.colSpan = 9;
            td.className = 'events-empty';
            td.textContent = state.events.length === 0 ? 'Waiting for events...' : 'No events match filters';
            tr.appendChild(td);
            tbody.appendChild(tr);
        } else {
            for (var i = 0; i < filtered.length; i++) {
                tbody.appendChild(createEventRow(filtered[i], false));
            }
        }

        updateEventCount(filtered.length);
    }

    function prependEvent(event) {
        state.events.unshift(event);
        // Cap stored events
        if (state.events.length > MAX_EVENTS) {
            state.events = state.events.slice(0, MAX_EVENTS);
        }

        if (!matchesFilter(event)) {
            updateEventCount();
            return;
        }

        var tbody = dom.eventsTbody;

        // Remove "Waiting for events" row if present
        var emptyRow = tbody.querySelector('.events-empty-row');
        if (emptyRow) {
            tbody.removeChild(emptyRow);
        }

        var row = createEventRow(event, true);
        if (tbody.firstChild) {
            tbody.insertBefore(row, tbody.firstChild);
        } else {
            tbody.appendChild(row);
        }

        // Trim visible rows
        while (tbody.children.length > MAX_EVENTS) {
            tbody.removeChild(tbody.lastChild);
        }

        updateEventCount();

        // Auto-scroll to top if user hasn't scrolled down significantly
        if (dom.eventsFeed.scrollTop < 100) {
            dom.eventsFeed.scrollTop = 0;
        }
    }

    function updateEventCount(filteredCount) {
        var total = state.events.length;
        if (filteredCount === undefined) {
            filteredCount = state.events.filter(matchesFilter).length;
        }
        dom.eventsCount.textContent = total + ' event' + (total !== 1 ? 's' : '');
        if (state.activeFilter !== 'all' || state.searchQuery) {
            dom.eventsFiltered.textContent = 'Showing ' + filteredCount + ' of ' + total;
        } else {
            dom.eventsFiltered.textContent = '';
        }
    }

    // =========================================================================
    // Data Fetching
    // =========================================================================

    function fetchStats() {
        fetch(STATS_URL)
            .then(function (res) { return res.json(); })
            .then(function (data) {
                if (data) {
                    // Merge stats, supporting various API response shapes
                    var s = state.stats;
                    s.total_requests = data.total_requests || data.totalRequests || s.total_requests;
                    s.blocked = data.blocked || s.blocked;
                    s.logged = data.logged || s.logged;
                    s.passed = data.passed || s.passed;
                    s.avg_latency_ms = data.avg_latency_ms || data.avgLatencyMs || s.avg_latency_ms;
                    s.p99_latency_ms = data.p99_latency_ms || data.p99LatencyMs || s.p99_latency_ms;
                    s.requests_per_second = data.requests_per_second || data.requestsPerSecond || s.requests_per_second;
                    if (data.attack_types || data.attackTypes) {
                        s.attack_types = data.attack_types || data.attackTypes;
                    }
                    if (data.top_ips || data.topIps) {
                        s.top_ips = data.top_ips || data.topIps;
                    }
                    renderStats();
                    renderAttackTypes();
                    renderTopIps();
                }
            })
            .catch(function (err) {
                console.warn('[GuardianWAF] Failed to fetch stats:', err);
            });
    }

    function fetchEvents() {
        fetch(EVENTS_URL + '?limit=50')
            .then(function (res) { return res.json(); })
            .then(function (data) {
                if (Array.isArray(data)) {
                    state.events = data;
                } else if (data && Array.isArray(data.events)) {
                    state.events = data.events;
                }
                renderEvents();
            })
            .catch(function (err) {
                console.warn('[GuardianWAF] Failed to fetch events:', err);
            });
    }

    // =========================================================================
    // SSE (Server-Sent Events) with Exponential Backoff
    // =========================================================================

    var sseSource = null;

    function connectSSE() {
        if (sseSource) {
            sseSource.close();
        }

        sseSource = new EventSource(SSE_URL);

        sseSource.onopen = function () {
            state.sseRetryDelay = 1000; // Reset backoff
            setSseStatus(true);
        };

        // Listen for "event" type messages
        sseSource.addEventListener('event', function (e) {
            try {
                var event = JSON.parse(e.data);
                prependEvent(event);
                incrementStats(event);
            } catch (err) {
                console.warn('[GuardianWAF] SSE parse error:', err);
            }
        });

        // Also handle default "message" events (fallback)
        sseSource.onmessage = function (e) {
            try {
                var data = JSON.parse(e.data);
                // Could be an event or stats update
                if (data.action || data.client_ip) {
                    prependEvent(data);
                    incrementStats(data);
                } else if (data.total_requests !== undefined || data.totalRequests !== undefined) {
                    // Stats update
                    var s = state.stats;
                    s.total_requests = data.total_requests || data.totalRequests || s.total_requests;
                    s.blocked = data.blocked || s.blocked;
                    s.logged = data.logged || s.logged;
                    s.passed = data.passed || s.passed;
                    renderStats();
                }
            } catch (err) {
                // Ignore unparseable messages (could be heartbeats)
            }
        };

        sseSource.onerror = function () {
            setSseStatus(false);
            sseSource.close();
            sseSource = null;

            // Exponential backoff reconnect
            var delay = state.sseRetryDelay;
            console.log('[GuardianWAF] SSE reconnecting in ' + delay + 'ms...');
            setTimeout(connectSSE, delay);
            state.sseRetryDelay = Math.min(state.sseRetryDelay * 2, state.sseMaxRetryDelay);
        };
    }

    function setSseStatus(connected) {
        if (connected) {
            dom.sseStatus.className = 'status-dot connected';
            dom.sseStatusLabel.textContent = 'Live';
        } else {
            dom.sseStatus.className = 'status-dot disconnected';
            dom.sseStatusLabel.textContent = 'Reconnecting...';
        }
    }

    /**
     * Incrementally update stats when a new event arrives via SSE.
     */
    function incrementStats(event) {
        var s = state.stats;
        s.total_requests++;
        if (event.action === 'block') s.blocked++;
        else if (event.action === 'log') s.logged++;
        else s.passed++;

        // Accumulate attack types from detectors array
        if (event.detectors && Array.isArray(event.detectors)) {
            for (var i = 0; i < event.detectors.length; i++) {
                var det = event.detectors[i];
                var name = det.name || det;
                if (typeof name === 'string' && name) {
                    s.attack_types[name] = (s.attack_types[name] || 0) + 1;
                }
            }
        }
        // Also handle flat detector_name field
        if (event.detector_name || event.detectorName) {
            var dname = event.detector_name || event.detectorName;
            s.attack_types[dname] = (s.attack_types[dname] || 0) + 1;
        }

        renderStats();
        renderAttackTypes();
    }

    // =========================================================================
    // Filter & Search Controls
    // =========================================================================

    function setupFilters() {
        var filterBtns = document.querySelectorAll('.filter-btn');
        for (var i = 0; i < filterBtns.length; i++) {
            filterBtns[i].addEventListener('click', function () {
                // Remove active from all
                for (var j = 0; j < filterBtns.length; j++) {
                    filterBtns[j].classList.remove('active');
                }
                this.classList.add('active');
                state.activeFilter = this.getAttribute('data-filter');
                renderEvents();
            });
        }

        var searchTimer = null;
        dom.searchInput.addEventListener('input', function () {
            clearTimeout(searchTimer);
            var self = this;
            searchTimer = setTimeout(function () {
                state.searchQuery = self.value.trim();
                renderEvents();
            }, 200);
        });
    }

    // =========================================================================
    // Periodic Refresh (Timestamps + Stats Polling)
    // =========================================================================

    function startTimestampRefresh() {
        setInterval(function () {
            var cells = dom.eventsTbody.querySelectorAll('td:first-child');
            var filtered = state.events.filter(matchesFilter);
            for (var i = 0; i < Math.min(cells.length, 50); i++) {
                var row = cells[i].parentNode;
                if (row.classList.contains('events-empty-row')) continue;
                if (i < filtered.length) {
                    cells[i].textContent = formatTimestamp(filtered[i].timestamp);
                }
            }
        }, 10000);
    }

    function startStatsPolling() {
        setInterval(fetchStats, STATS_POLL_INTERVAL);
    }

    // =========================================================================
    // Initialization
    // =========================================================================

    function init() {
        cacheDom();
        setupFilters();

        // Initial data load
        fetchStats();
        fetchEvents();

        // Connect SSE for real-time updates
        connectSSE();

        // Periodic refreshes
        startTimestampRefresh();
        startStatsPolling();
    }

    // Start when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
