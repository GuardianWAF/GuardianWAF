// GuardianWAF Dashboard - Vanilla JavaScript

(function () {
    "use strict";

    // ---------------------------------------------------------------------------
    // State
    // ---------------------------------------------------------------------------
    var currentPage = "dashboard";
    var currentRulesTab = "whitelist";
    var eventsPage = 0;
    var eventsLimit = 50;
    var sseSource = null;

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------
    function $(sel) { return document.querySelector(sel); }
    function $$(sel) { return document.querySelectorAll(sel); }

    function apiGet(path) {
        return fetch(path).then(function (r) { return r.json(); });
    }

    function apiPost(path, body) {
        return fetch(path, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        }).then(function (r) { return r.json(); });
    }

    function apiDelete(path) {
        return fetch(path, { method: "DELETE" }).then(function (r) { return r.json(); });
    }

    function formatTime(ts) {
        if (!ts) return "-";
        var d = new Date(ts);
        return d.toLocaleTimeString();
    }

    function formatDuration(ns) {
        if (!ns) return "-";
        if (ns < 1000) return ns + "ns";
        if (ns < 1000000) return (ns / 1000).toFixed(1) + "us";
        if (ns < 1000000000) return (ns / 1000000).toFixed(1) + "ms";
        return (ns / 1000000000).toFixed(2) + "s";
    }

    function actionClass(action) {
        if (!action) return "";
        var a = action.toString().toLowerCase();
        if (a === "block" || a === "1") return "action-blocked";
        if (a === "log" || a === "2") return "action-logged";
        return "action-passed";
    }

    function actionLabel(action) {
        if (typeof action === "number") {
            switch (action) {
                case 0: return "pass";
                case 1: return "block";
                case 2: return "log";
                case 3: return "challenge";
                default: return "unknown";
            }
        }
        return action || "pass";
    }

    // Safe DOM helper: create a table cell with text content only
    function td(text) {
        var cell = document.createElement("td");
        cell.textContent = text;
        return cell;
    }

    // Safe DOM helper: create a table cell with a CSS class and text
    function tdClass(text, cls) {
        var cell = document.createElement("td");
        cell.textContent = text;
        if (cls) cell.className = cls;
        return cell;
    }

    // Clear all child nodes from an element
    function clearChildren(el) {
        while (el.firstChild) {
            el.removeChild(el.firstChild);
        }
    }

    // ---------------------------------------------------------------------------
    // Navigation
    // ---------------------------------------------------------------------------
    function switchPage(page) {
        currentPage = page;
        $$(".page").forEach(function (el) { el.classList.remove("active"); });
        $$(".tab").forEach(function (el) { el.classList.remove("active"); });
        var target = $("#page-" + page);
        if (target) target.classList.add("active");
        $$('.tab[data-page="' + page + '"]').forEach(function (el) { el.classList.add("active"); });

        if (page === "events") refreshEvents();
        if (page === "config") refreshConfig();
        if (page === "rules") refreshRules();
    }

    $$(".tab").forEach(function (btn) {
        btn.addEventListener("click", function () {
            switchPage(this.getAttribute("data-page"));
        });
    });

    // ---------------------------------------------------------------------------
    // Theme Toggle
    // ---------------------------------------------------------------------------
    function applyTheme(theme) {
        document.documentElement.setAttribute("data-theme", theme);
        var btn = $("#theme-toggle");
        btn.textContent = theme === "dark" ? "\u2600" : "\u263E";
        try { localStorage.setItem("guardianwaf-theme", theme); } catch (e) {}
    }

    (function initTheme() {
        var saved = "dark";
        try { saved = localStorage.getItem("guardianwaf-theme") || "dark"; } catch (e) {}
        applyTheme(saved);
    })();

    $("#theme-toggle").addEventListener("click", function () {
        var current = document.documentElement.getAttribute("data-theme");
        applyTheme(current === "dark" ? "light" : "dark");
    });

    // ---------------------------------------------------------------------------
    // Stats (auto-refresh)
    // ---------------------------------------------------------------------------
    function refreshStats() {
        apiGet("/api/v1/stats").then(function (data) {
            $("#total-requests").textContent = data.total_requests || 0;
            $("#blocked-requests").textContent = data.blocked_requests || 0;
            $("#logged-requests").textContent = data.logged_requests || 0;
            $("#passed-requests").textContent = data.passed_requests || 0;
            var lat = data.avg_latency_us || 0;
            if (lat < 1000) {
                $("#avg-latency").textContent = lat + "us";
            } else {
                $("#avg-latency").textContent = (lat / 1000).toFixed(1) + "ms";
            }
        }).catch(function () {});
    }

    function refreshRecentEvents() {
        apiGet("/api/v1/events?limit=10&sort_order=desc").then(function (data) {
            var tbody = $("#recent-events-table tbody");
            clearChildren(tbody);
            var events = data.events || [];
            events.forEach(function (ev) {
                var tr = document.createElement("tr");
                tr.appendChild(td(formatTime(ev.Timestamp)));
                tr.appendChild(td(ev.ClientIP || "-"));
                tr.appendChild(td(ev.Method || "-"));
                tr.appendChild(td(ev.Path || "-"));
                tr.appendChild(td(String(ev.Score || 0)));
                tr.appendChild(tdClass(actionLabel(ev.Action), actionClass(ev.Action)));
                tbody.appendChild(tr);
            });
        }).catch(function () {});
    }

    setInterval(function () {
        if (currentPage === "dashboard") {
            refreshStats();
            refreshRecentEvents();
        }
    }, 2000);

    refreshStats();
    refreshRecentEvents();

    // ---------------------------------------------------------------------------
    // Events Page
    // ---------------------------------------------------------------------------
    function refreshEvents() {
        var action = $("#action-filter").value;
        var ip = $("#ip-filter").value;
        var offset = eventsPage * eventsLimit;
        var url = "/api/v1/events?limit=" + eventsLimit + "&offset=" + offset + "&sort_order=desc";
        if (action) url += "&action=" + action;
        if (ip) url += "&client_ip=" + encodeURIComponent(ip);

        apiGet(url).then(function (data) {
            var tbody = $("#events-table tbody");
            clearChildren(tbody);
            var events = data.events || [];
            events.forEach(function (ev) {
                var tr = document.createElement("tr");
                tr.appendChild(td(formatTime(ev.Timestamp)));
                tr.appendChild(td(ev.ClientIP || "-"));
                tr.appendChild(td(ev.Method || "-"));
                tr.appendChild(td(ev.Path || "-"));
                tr.appendChild(td(String(ev.Score || 0)));
                tr.appendChild(tdClass(actionLabel(ev.Action), actionClass(ev.Action)));
                tr.appendChild(td(formatDuration(ev.Duration)));
                tbody.appendChild(tr);
            });

            var total = data.total || 0;
            var totalPages = Math.ceil(total / eventsLimit) || 1;
            $("#page-info").textContent = "Page " + (eventsPage + 1) + " of " + totalPages;
            $("#prev-page").disabled = eventsPage === 0;
            $("#next-page").disabled = (eventsPage + 1) >= totalPages;
        }).catch(function () {});
    }

    $("#refresh-events").addEventListener("click", refreshEvents);
    $("#action-filter").addEventListener("change", function () { eventsPage = 0; refreshEvents(); });

    $("#prev-page").addEventListener("click", function () {
        if (eventsPage > 0) { eventsPage--; refreshEvents(); }
    });
    $("#next-page").addEventListener("click", function () {
        eventsPage++; refreshEvents();
    });

    // ---------------------------------------------------------------------------
    // Config Page
    // ---------------------------------------------------------------------------
    function refreshConfig() {
        apiGet("/api/v1/config").then(function (data) {
            $("#config-display").textContent = JSON.stringify(data, null, 2);
        }).catch(function () {
            $("#config-display").textContent = "Failed to load configuration.";
        });
    }

    $("#reload-config").addEventListener("click", function () {
        apiPost("/api/v1/config/reload", {}).then(function (data) {
            alert(data.message || "Config reloaded");
            refreshConfig();
        }).catch(function () { alert("Failed to reload config"); });
    });

    // ---------------------------------------------------------------------------
    // Rules Page
    // ---------------------------------------------------------------------------
    $$(".rules-tab").forEach(function (btn) {
        btn.addEventListener("click", function () {
            $$(".rules-tab").forEach(function (b) { b.classList.remove("active"); });
            this.classList.add("active");
            currentRulesTab = this.getAttribute("data-rules");
            refreshRules();
        });
    });

    function refreshRules() {
        apiGet("/api/v1/rules/" + currentRulesTab).then(function (data) {
            var tbody = $("#rules-table tbody");
            clearChildren(tbody);
            var rules = data.rules || [];
            rules.forEach(function (rule) {
                var tr = document.createElement("tr");
                var val = rule.value || rule.path || rule.Value || rule.Path || "-";
                var reason = rule.reason || rule.Reason || "";
                if (rule.limit) {
                    reason = "Limit: " + rule.limit + " / " + (rule.window || "?");
                }
                tr.appendChild(td(rule.id || rule.ID || "-"));
                tr.appendChild(td(val));
                tr.appendChild(td(reason));

                var actionCell = document.createElement("td");
                var delBtn = document.createElement("button");
                delBtn.className = "btn btn-danger btn-sm";
                delBtn.textContent = "Delete";
                delBtn.setAttribute("data-id", rule.id || rule.ID);
                delBtn.addEventListener("click", function () {
                    var rid = this.getAttribute("data-id");
                    apiDelete("/api/v1/rules/" + currentRulesTab + "/" + rid).then(refreshRules);
                });
                actionCell.appendChild(delBtn);
                tr.appendChild(actionCell);

                tbody.appendChild(tr);
            });
        }).catch(function () {});
    }

    $("#add-rule").addEventListener("click", function () {
        var value = $("#rule-value").value.trim();
        var reason = $("#rule-reason").value.trim();
        if (!value) return;

        var body;
        if (currentRulesTab === "ratelimit") {
            body = { path: value, limit: 100, window: "1m", action: "block" };
        } else if (currentRulesTab === "exclusions") {
            body = { path: value, detectors: [], reason: reason };
        } else {
            body = { value: value, reason: reason };
        }

        apiPost("/api/v1/rules/" + currentRulesTab, body).then(function () {
            $("#rule-value").value = "";
            $("#rule-reason").value = "";
            refreshRules();
        });
    });

    // ---------------------------------------------------------------------------
    // SSE
    // ---------------------------------------------------------------------------
    function connectSSE() {
        if (sseSource) {
            sseSource.close();
        }

        var dot = $("#sse-status");
        sseSource = new EventSource("/api/v1/sse");

        sseSource.onopen = function () {
            dot.classList.remove("disconnected");
            dot.classList.add("connected");
            dot.title = "SSE connected";
        };

        sseSource.onmessage = function (e) {
            try {
                var msg = JSON.parse(e.data);
                if (msg.type === "event" && currentPage === "dashboard") {
                    refreshStats();
                    refreshRecentEvents();
                }
            } catch (err) {}
        };

        sseSource.onerror = function () {
            dot.classList.remove("connected");
            dot.classList.add("disconnected");
            dot.title = "SSE disconnected";
            sseSource.close();
            setTimeout(connectSSE, 5000);
        };
    }

    connectSSE();
})();
