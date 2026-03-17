(function () {
    "use strict";

    var originalConfig = null;
    var dirty = false;

    // --- Init ---
    document.addEventListener("DOMContentLoaded", function () {
        fetchConfig();
    });

    // --- Fetch config ---
    function fetchConfig() {
        fetch("/api/v1/config")
            .then(function (r) { return r.json(); })
            .then(function (data) {
                originalConfig = JSON.parse(JSON.stringify(data));
                populateForm(data);
                updateBadges(data);
                dirty = false;
                document.getElementById("save-bar").classList.remove("visible");
            })
            .catch(function (err) {
                showToast("Failed to load config: " + err, true);
            });
    }

    // --- Populate form from config ---
    function populateForm(cfg) {
        // Selects
        var selects = document.querySelectorAll("select[data-path]");
        for (var i = 0; i < selects.length; i++) {
            var val = getNestedValue(cfg, selects[i].getAttribute("data-path"));
            if (val !== undefined) selects[i].value = val;
        }

        // Checkboxes
        var checks = document.querySelectorAll('input[type="checkbox"][data-path]');
        for (var j = 0; j < checks.length; j++) {
            var v = getNestedValue(cfg, checks[j].getAttribute("data-path"));
            checks[j].checked = !!v;
        }

        // Number inputs
        var nums = document.querySelectorAll('input[type="number"][data-path]');
        for (var k = 0; k < nums.length; k++) {
            var n = getNestedValue(cfg, nums[k].getAttribute("data-path"));
            if (n !== undefined) nums[k].value = n;
        }

        // Detectors grid
        renderDetectors(cfg);
    }

    // --- Render detector cards using safe DOM methods ---
    function renderDetectors(cfg) {
        var grid = document.getElementById("detectors-grid");
        if (!grid) return;
        // Clear existing children safely
        while (grid.firstChild) grid.removeChild(grid.firstChild);

        var detectors = (cfg.waf && cfg.waf.detection && cfg.waf.detection.detectors) || {};
        var names = Object.keys(detectors).sort();
        var labels = { sqli: "SQL Injection", xss: "XSS", lfi: "Path Traversal", cmdi: "Command Injection", xxe: "XXE", ssrf: "SSRF" };

        for (var i = 0; i < names.length; i++) {
            var name = names[i];
            var det = detectors[name];
            var card = document.createElement("div");
            card.className = "detector-card";

            // Left side: label + multiplier
            var left = document.createElement("div");
            var nameDiv = document.createElement("div");
            nameDiv.className = "detector-name";
            nameDiv.textContent = labels[name] || name.toUpperCase();
            left.appendChild(nameDiv);

            var multDiv = document.createElement("div");
            multDiv.className = "multiplier";
            multDiv.style.marginTop = "4px";
            var xSpan = document.createElement("span");
            xSpan.style.fontSize = ".75rem";
            xSpan.style.color = "var(--text-secondary)";
            xSpan.textContent = "x";
            multDiv.appendChild(xSpan);
            var multInput = document.createElement("input");
            multInput.type = "number";
            multInput.className = "num-input";
            multInput.step = "0.1";
            multInput.min = "0";
            multInput.max = "5";
            multInput.value = det.Multiplier || det.multiplier || 1;
            multInput.style.width = "50px";
            multInput.setAttribute("data-detector", name);
            multInput.setAttribute("data-field", "multiplier");
            multInput.addEventListener("change", markDirty);
            multDiv.appendChild(multInput);
            left.appendChild(multDiv);
            card.appendChild(left);

            // Right side: toggle
            var toggleLabel = document.createElement("label");
            toggleLabel.className = "toggle";
            var toggleInput = document.createElement("input");
            toggleInput.type = "checkbox";
            toggleInput.checked = !!(det.Enabled || det.enabled);
            toggleInput.setAttribute("data-detector", name);
            toggleInput.setAttribute("data-field", "enabled");
            toggleInput.addEventListener("change", markDirty);
            toggleLabel.appendChild(toggleInput);
            var slider = document.createElement("span");
            slider.className = "toggle-slider";
            toggleLabel.appendChild(slider);
            card.appendChild(toggleLabel);

            grid.appendChild(card);
        }
    }

    // --- Update section badges ---
    function updateBadges(cfg) {
        setBadge("badge-detection", cfg.waf && cfg.waf.detection && cfg.waf.detection.enabled);
        setBadge("badge-ratelimit", cfg.waf && cfg.waf.rate_limit && cfg.waf.rate_limit.enabled);
        setBadge("badge-bot", cfg.waf && cfg.waf.bot_detection && cfg.waf.bot_detection.enabled);
        setBadge("badge-challenge", cfg.waf && cfg.waf.challenge && cfg.waf.challenge.enabled);
        setBadge("badge-ipacl", cfg.waf && cfg.waf.ip_acl && cfg.waf.ip_acl.enabled);
        setBadge("badge-sanitizer", cfg.waf && cfg.waf.sanitizer && cfg.waf.sanitizer.enabled);
        setBadge("badge-response", cfg.waf && cfg.waf.response && cfg.waf.response.security_headers && cfg.waf.response.security_headers.enabled);
    }

    function setBadge(id, on) {
        var el = document.getElementById(id);
        if (!el) return;
        el.textContent = on ? "ON" : "OFF";
        el.className = "section-badge " + (on ? "section-badge--on" : "section-badge--off");
    }

    // --- Build config patch from form ---
    function buildPatch() {
        var patch = {};

        // Selects
        var selects = document.querySelectorAll("select[data-path]");
        for (var i = 0; i < selects.length; i++) {
            setNestedValue(patch, selects[i].getAttribute("data-path"), selects[i].value);
        }

        // Checkboxes
        var checks = document.querySelectorAll('input[type="checkbox"][data-path]');
        for (var j = 0; j < checks.length; j++) {
            setNestedValue(patch, checks[j].getAttribute("data-path"), checks[j].checked);
        }

        // Number inputs
        var nums = document.querySelectorAll('input[type="number"][data-path]');
        for (var k = 0; k < nums.length; k++) {
            var val = parseFloat(nums[k].value);
            if (!isNaN(val)) setNestedValue(patch, nums[k].getAttribute("data-path"), val);
        }

        // Detectors
        var detInputs = document.querySelectorAll("[data-detector]");
        if (detInputs.length > 0) {
            if (!patch.waf) patch.waf = {};
            if (!patch.waf.detection) patch.waf.detection = {};
            if (!patch.waf.detection.detectors) patch.waf.detection.detectors = {};

            for (var d = 0; d < detInputs.length; d++) {
                var inp = detInputs[d];
                var dname = inp.getAttribute("data-detector");
                var field = inp.getAttribute("data-field");
                if (!patch.waf.detection.detectors[dname]) patch.waf.detection.detectors[dname] = {};
                if (field === "enabled") {
                    patch.waf.detection.detectors[dname].enabled = inp.checked;
                } else if (field === "multiplier") {
                    patch.waf.detection.detectors[dname].multiplier = parseFloat(inp.value) || 1;
                }
            }
        }

        return patch;
    }

    // --- Save config ---
    window.saveConfig = function () {
        var patch = buildPatch();
        var statusEl = document.getElementById("save-status");
        statusEl.textContent = "Saving...";

        fetch("/api/v1/config", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(patch)
        })
            .then(function (r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
            .then(function (res) {
                if (res.ok) {
                    showToast("Configuration saved and applied!", false);
                    dirty = false;
                    document.getElementById("save-bar").classList.remove("visible");
                    fetchConfig(); // reload fresh state
                } else {
                    showToast("Error: " + (res.data.error || "Unknown error"), true);
                    statusEl.textContent = "Save failed";
                }
            })
            .catch(function (err) {
                showToast("Network error: " + err, true);
                statusEl.textContent = "Save failed";
            });
    };

    // --- Reset / discard ---
    window.resetConfig = function () {
        if (originalConfig) {
            populateForm(originalConfig);
            updateBadges(originalConfig);
        }
        dirty = false;
        document.getElementById("save-bar").classList.remove("visible");
    };

    // --- Mark dirty ---
    window.markDirty = function () {
        if (!dirty) {
            dirty = true;
            document.getElementById("save-bar").classList.add("visible");
            document.getElementById("save-status").textContent = "Unsaved changes";
        }
        // Update badges live
        var liveCfg = buildPatch();
        updateBadges(liveCfg);
    };

    // --- Section toggle ---
    window.toggleSection = function (headerEl) {
        headerEl.parentElement.classList.toggle("collapsed");
    };

    // --- Helpers ---
    function getNestedValue(obj, path) {
        var parts = path.split(".");
        var cur = obj;
        for (var i = 0; i < parts.length; i++) {
            if (cur === undefined || cur === null) return undefined;
            cur = cur[parts[i]];
        }
        return cur;
    }

    function setNestedValue(obj, path, value) {
        var parts = path.split(".");
        var cur = obj;
        for (var i = 0; i < parts.length - 1; i++) {
            if (!cur[parts[i]]) cur[parts[i]] = {};
            cur = cur[parts[i]];
        }
        cur[parts[parts.length - 1]] = value;
    }

    function showToast(msg, isError) {
        var toast = document.createElement("div");
        toast.className = "toast " + (isError ? "toast--err" : "toast--ok");
        toast.textContent = msg;
        document.body.appendChild(toast);
        setTimeout(function () {
            toast.style.opacity = "0";
            toast.style.transition = "opacity .3s";
            setTimeout(function () { toast.remove(); }, 300);
        }, 3000);
    }
})();
