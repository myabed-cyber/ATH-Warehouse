/* WOW UI bindings -> ATH Warehouse Hub backend
   Goal: keep WOW presentation layer, wire ALL core functions from original ATH project.
   - Auth: /api/auth/login, /api/auth/me
   - Scan (idempotent + DB): /api/scans/parse-validate
   - Cases: /api/cases (create/list/detail/update)
   - Commit: /api/postings/commit (+ legacy /api/commit)
   - Admin: /api/users, /api/audit, /api/policies/active, /api/gtin-map(/upsert), /api/items-cache, /api/work-sessions, /api/tx-log
*/

(function () {
  "use strict";

  // ---------------- Utilities ----------------
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const el = (id) => document.getElementById(id);

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  const escapeHtml = (s) =>
    String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");

  const fmtDate = (d) => {
    try {
      const dt = new Date(d);
      if (Number.isNaN(dt.getTime())) return String(d ?? "");
      return dt.toLocaleString();
    } catch {
      return String(d ?? "");
    }
  };

  const uuid = () => {
    // RFC4122-ish, good enough for idempotency keys
    if (crypto && crypto.randomUUID) return crypto.randomUUID();
    const r = () => Math.floor(Math.random() * 0xffffffff).toString(16).padStart(8, "0");
    return `${r()}-${r().slice(0, 4)}-${r().slice(0, 4)}-${r().slice(0, 4)}-${r()}${r().slice(0, 4)}`;
  };

  function toast(message, type = "info", opts = {}) {
    const area = el("toastArea") || $(".toast-container");
    if (!area) return console.log("[toast]", type, message);

    const tone = {
      success: {
        accent: "var(--tactical-green)",
        bg: "rgba(16, 185, 129, 0.12)",
        border: "rgba(16, 185, 129, 0.25)",
        icon: "ph-check-circle",
      },
      error: {
        accent: "var(--tactical-red)",
        bg: "rgba(239, 68, 68, 0.12)",
        border: "rgba(239, 68, 68, 0.25)",
        icon: "ph-warning-circle",
      },
      warn: {
        accent: "var(--tactical-amber)",
        bg: "rgba(245, 158, 11, 0.12)",
        border: "rgba(245, 158, 11, 0.25)",
        icon: "ph-warning",
      },
      info: {
        accent: "var(--brand-primary)",
        bg: "rgba(59, 130, 246, 0.10)",
        border: "rgba(59, 130, 246, 0.20)",
        icon: "ph-info",
      },
    };

    const tTone = tone[type] || tone.info;

    const t = document.createElement("div");
    t.className = "toast";

    const actionHtml =
      opts.action && opts.action.label
        ? `<button class="btn secondary" style="padding:8px 10px; font-size:12px; margin-left:10px; border-color:${tTone.border}; color:${tTone.accent}; background:transparent;">
             ${escapeHtml(opts.action.label)}
           </button>`
        : "";

    t.innerHTML = `
      <div style="width: 34px; height: 34px; border-radius: 12px; display:grid; place-items:center; background:${tTone.bg}; color:${tTone.accent}; border:1px solid ${tTone.border}">
        <i class="ph-bold ${tTone.icon}"></i>
      </div>
      <div style="display:flex; flex-direction:column; line-height:1.2;">
        <div style="font-weight:800; font-size:12px; color:${tTone.accent}">${escapeHtml(opts.title || "Notification")}</div>
        <div style="font-size:12px; color: var(--text-main); opacity:.92;">${escapeHtml(message)}</div>
      </div>
      ${actionHtml}
    `;

    if (opts.action && opts.action.onClick) {
      const btn = $("button", t);
      if (btn) btn.addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); opts.action.onClick(); });
    }

    area.appendChild(t);
    const ttl = opts.ttl ?? (type === "error" ? 6500 : 3500);
    setTimeout(() => {
      t.style.opacity = "0";
      setTimeout(() => t.remove(), 260);
    }, ttl);
  }

  const sfx = () => (window.sfx && typeof window.sfx.play === "function" ? window.sfx : null);

  // ---------------- API ----------------
  const storageKey = "ath_token";
  const state = {
    token: null,
    user: null,
    role: null,
    activeTab: "overview",
    lastScan: null,          // {scan_id, raw_string, result}
    zxingReady: false,
    scannerBusy: false,
    pagesReady: false,
  };

  function setToken(tok) {
    state.token = tok || null;
    if (tok) localStorage.setItem(storageKey, tok);
    else localStorage.removeItem(storageKey);
  }

  function authHeaders(extra = {}) {
    const h = { "Content-Type": "application/json", ...extra };
    if (state.token) h.Authorization = `Bearer ${state.token}`;
    return h;
  }

  async function api(path, { method = "GET", body = null, headers = {} } = {}) {
    const res = await fetch(path, {
      method,
      headers: authHeaders(headers),
      body: body ? JSON.stringify(body) : null,
    });
    let data = null;
    try {
      data = await res.json();
    } catch {
      data = null;
    }
    if (!res.ok) {
      const errMsg = data?.error || data?.message || res.statusText || "Request failed";
      const e = new Error(errMsg);
      e.status = res.status;
      e.data = data;
      throw e;
    }
    return data;
  }

  // ---------------- View helpers ----------------
  function showView(view) {
    const login = el("view-login");
    const dash = el("view-dashboard");
    if (!login || !dash) return;

    if (view === "dashboard") {
      login.classList.remove("active");
      dash.classList.add("active");
    } else {
      dash.classList.remove("active");
      login.classList.add("active");
    }
  }

  function setUserProfile(username, role) {
    // sidebar profile block has no ids; find best match
    const sidebar = $(".sidebar");
    if (!sidebar) return;

    const nameEl = sidebar.querySelector(".user-profile div[style*='font-weight: 700']");
    const roleEl = sidebar.querySelector(".user-profile div[style*='opacity']");
    if (nameEl) nameEl.textContent = username || "User";
    if (roleEl) roleEl.textContent = role ? role.toUpperCase() : "ROLE";
  }

  function setActiveNavByIndex(idx) {
    const navItems = $$(".nav-item");
    navItems.forEach((n, i) => n.classList.toggle("active", i === idx));
  }

  function showTab(tab) {
    state.activeTab = tab;
    const idx = tab === "overview" ? 0 : tab === "inventory" ? 1 : tab === "shipments" ? 2 : 3;
    setActiveNavByIndex(idx);

    const pages = $$(".wow-page");
    pages.forEach((p) => {
      p.style.display = p.dataset.page === tab ? "" : "none";
    });
  }

  // ---------------- Page construction ----------------
  function ensurePages() {
    if (state.pagesReady) return;
    const scroll = $("#view-dashboard .scroll-area");
    if (!scroll) return;

    // Move current overview content into its own container (keeps exact WOW markup)
    const overview = document.createElement("div");
    overview.className = "wow-page";
    overview.dataset.page = "overview";

    while (scroll.firstChild) overview.appendChild(scroll.firstChild);
    scroll.appendChild(overview);

    const inventory = document.createElement("div");
    inventory.className = "wow-page";
    inventory.dataset.page = "inventory";
    inventory.style.display = "none";
    inventory.innerHTML = `
      <div class="glass-panel" style="margin-bottom:18px;">
        <div class="data-table-header">
          <div style="display:flex; align-items:center; gap:10px;">
            <i class="ph-bold ph-cube" style="color: var(--brand-primary)"></i>
            <div style="font-weight: 800;">Inventory</div>
          </div>
          <div style="display:flex; gap:10px;">
            <button class="btn secondary" id="invRefreshBtn"><i class="ph-bold ph-arrow-clockwise"></i> Refresh</button>
            <button class="btn secondary" id="invSyncBtn" style="display:none;"><i class="ph-bold ph-cloud-arrow-up"></i> Sync from BC</button>
          </div>
        </div>
        <div style="display:grid; grid-template-columns: 1.1fr .9fr; gap:14px;">
          <div class="glass-panel" style="padding:16px; margin:0;">
            <div style="font-weight:700; margin-bottom:10px;">Top 200 Items</div>
            <div class="search-pill" style="margin-bottom:12px;">
              <i class="ph-bold ph-magnifying-glass"></i>
              <input id="invItemSearch" placeholder="Search item name / item no..." />
            </div>
            <div style="max-height: 360px; overflow:auto;">
              <table class="data-table">
                <thead><tr><th>Item No</th><th>Item Name</th></tr></thead>
                <tbody id="invItemsBody"><tr><td colspan="2" style="opacity:.7;">Loading...</td></tr></tbody>
              </table>
            </div>
          </div>

          <div class="glass-panel" style="padding:16px; margin:0;">
            <div style="font-weight:700; margin-bottom:10px;">GTIN Mapping</div>
            <div style="display:grid; gap:10px;">
              <div style="display:grid; grid-template-columns: 1fr 1fr; gap:10px;">
                <input id="mapGtin" placeholder="GTIN (AI 01)" style="padding:12px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white;" />
                <input id="mapItem" placeholder="Item No" style="padding:12px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white;" />
              </div>
              <div style="display:flex; gap:10px; flex-wrap:wrap;">
                <button class="btn primary" id="mapOperatorBtn"><i class="ph-bold ph-link"></i> Map (Operator)</button>
                <button class="btn secondary" id="mapAdminBtn" style="display:none;"><i class="ph-bold ph-shield-check"></i> Upsert (Admin)</button>
              </div>
              <div style="font-size: 12px; opacity: .8;" id="mapHint">
                Operator mapping validates Item No exists in Items Cache (Top200) and logs audit trail.
              </div>

              <div id="adminMapListWrap" style="display:none;">
                <div style="font-weight:700; margin-top:10px; margin-bottom:8px;">Recent Mappings (Admin)</div>
                <div class="search-pill" style="margin-bottom:10px;">
                  <i class="ph-bold ph-magnifying-glass"></i>
                  <input id="mapSearch" placeholder="Search GTIN or Item No..." />
                </div>
                <div style="max-height: 240px; overflow:auto;">
                  <table class="data-table">
                    <thead><tr><th>GTIN</th><th>Item No</th><th>Status</th></tr></thead>
                    <tbody id="mapBody"><tr><td colspan="3" style="opacity:.7;">—</td></tr></tbody>
                  </table>
                </div>
              </div>

            </div>
          </div>
        </div>
      </div>
    `;
    scroll.appendChild(inventory);

    const shipments = document.createElement("div");
    shipments.className = "wow-page";
    shipments.dataset.page = "shipments";
    shipments.style.display = "none";
    shipments.innerHTML = `
      <div class="glass-panel" style="margin-bottom:18px;">
        <div class="data-table-header">
          <div style="display:flex; align-items:center; gap:10px;">
            <i class="ph-bold ph-truck" style="color: var(--brand-primary)"></i>
            <div style="font-weight: 800;">Shipments</div>
          </div>
          <div style="display:flex; gap:10px;">
            <button class="btn secondary" id="shipRefreshBtn"><i class="ph-bold ph-arrow-clockwise"></i> Refresh</button>
          </div>
        </div>

        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:14px;">
          <div class="glass-panel" style="padding:16px; margin:0;">
            <div style="display:flex; align-items:center; justify-content:space-between; gap:10px;">
              <div style="font-weight:700;">Commit Posting (BC)</div>
              <div class="badge" id="commitModeBadge">SIMULATED</div>
            </div>

            <div style="margin-top:12px; display:grid; gap:10px;">
              <div style="display:grid; grid-template-columns: 1fr; gap:10px;">
                <input id="commitScanId" placeholder="Scan ID (from last scan)" style="padding:12px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white;" />
              </div>

              <div style="display:flex; gap:10px; flex-wrap:wrap;">
                <button class="btn primary" id="commitPR"><i class="ph-bold ph-receipt"></i> Purchase Receipt</button>
                <button class="btn secondary" id="commitTR"><i class="ph-bold ph-arrow-right"></i> Transfer Receipt</button>
              </div>

              <div style="font-size:12px; opacity:.75;">
                Uses <code>/api/postings/commit</code> with Idempotency-Key. Requires the scan to exist in DB.
              </div>

              <div id="commitOut" style="margin-top:8px; font-size:12px; opacity:.9;"></div>
            </div>
          </div>

          <div class="glass-panel" style="padding:16px; margin:0;">
            <div style="font-weight:700; margin-bottom:10px;">Legacy Commit (UI Compatibility)</div>
            <div style="display:grid; gap:10px;">
              <textarea id="legacyRaw" rows="3" placeholder="Raw barcode payload..." style="padding:12px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white; resize: vertical;"></textarea>
              <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
                <select id="legacyType" style="padding:12px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white;">
                  <option value="RECEIPT">RECEIPT</option>
                  <option value="TRANSFER">TRANSFER</option>
                </select>
                <button class="btn secondary" id="legacyCommitBtn"><i class="ph-bold ph-paper-plane-tilt"></i> Commit</button>
              </div>
              <div id="legacyOut" style="margin-top:6px; font-size:12px; opacity:.9;"></div>
            </div>
          </div>
        </div>

        <div class="glass-panel" style="padding:16px; margin:14px 0 0 0;">
          <div style="display:flex; align-items:center; justify-content:space-between; gap:10px;">
            <div style="font-weight:700;">Work Sessions</div>
            <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
              <select id="wsStatus" style="padding:10px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white;">
                <option value="">All</option>
                <option value="OPEN">OPEN</option>
                <option value="CLOSED">CLOSED</option>
              </select>
              <button class="btn secondary" id="wsLoadBtn"><i class="ph-bold ph-list"></i> Load</button>
              <button class="btn secondary" id="wsCreateBtn" style="display:none;"><i class="ph-bold ph-plus"></i> Create (Admin)</button>
            </div>
          </div>

          <div style="display:grid; grid-template-columns: .9fr 1.1fr; gap:14px; margin-top:12px;">
            <div>
              <div style="font-size:12px; opacity:.8; margin-bottom:8px;">Sessions</div>
              <div style="max-height: 320px; overflow:auto;">
                <table class="data-table">
                  <thead><tr><th>Type</th><th>Status</th><th>Ref</th></tr></thead>
                  <tbody id="wsBody"><tr><td colspan="3" style="opacity:.7;">—</td></tr></tbody>
                </table>
              </div>
            </div>
            <div>
              <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
                <div style="font-size:12px; opacity:.8;">Session Lines</div>
                <div style="display:flex; gap:10px; flex-wrap:wrap;">
                  <button class="btn secondary" id="wsLinesBtn"><i class="ph-bold ph-arrows-clockwise"></i> Lines</button>
                  <button class="btn secondary" id="wsAddLinesBtn" style="display:none;"><i class="ph-bold ph-plus-circle"></i> Add Lines (Admin)</button>
                </div>
              </div>
              <div style="max-height: 320px; overflow:auto; margin-top:8px;">
                <table class="data-table">
                  <thead><tr><th>Item</th><th>Expected</th><th>Scanned</th><th>Remain</th></tr></thead>
                  <tbody id="wsLinesBody"><tr><td colspan="4" style="opacity:.7;">Select a session…</td></tr></tbody>
                </table>
              </div>
              <div id="wsOps" style="margin-top:10px; font-size:12px; opacity:.85;"></div>
            </div>
          </div>
        </div>
      </div>
    `;
    scroll.appendChild(shipments);

    const staff = document.createElement("div");
    staff.className = "wow-page";
    staff.dataset.page = "staff";
    staff.style.display = "none";
    staff.innerHTML = `
      <div class="glass-panel" style="margin-bottom:18px;">
        <div class="data-table-header">
          <div style="display:flex; align-items:center; gap:10px;">
            <i class="ph-bold ph-users" style="color: var(--brand-primary)"></i>
            <div style="font-weight: 800;">Staff & Admin</div>
          </div>
          <div style="display:flex; gap:10px;">
            <button class="btn secondary" id="staffRefreshBtn"><i class="ph-bold ph-arrow-clockwise"></i> Refresh</button>
          </div>
        </div>

        <div style="display:grid; grid-template-columns: 1.1fr .9fr; gap:14px;">
          <div class="glass-panel" style="padding:16px; margin:0;">
            <div style="display:flex; align-items:center; justify-content:space-between; gap:10px;">
              <div style="font-weight:700;">Cases</div>
              <div style="display:flex; gap:10px; flex-wrap:wrap;">
                <select id="caseStatus" style="padding:10px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white;">
                  <option value="">All Status</option>
                  <option value="NEW">NEW</option>
                  <option value="IN_PROGRESS">IN_PROGRESS</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="CLOSED">CLOSED</option>
                </select>
                <select id="caseDecision" style="padding:10px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white;">
                  <option value="">All Decisions</option>
                  <option value="WARN">WARN</option>
                  <option value="BLOCK">BLOCK</option>
                </select>
              </div>
            </div>
            <div class="search-pill" style="margin:12px 0;">
              <i class="ph-bold ph-magnifying-glass"></i>
              <input id="caseSearch" placeholder="Search scan id / raw..." />
            </div>

            <div style="max-height: 360px; overflow:auto;">
              <table class="data-table">
                <thead><tr><th>ID</th><th>Status</th><th>Decision</th><th>Scan</th></tr></thead>
                <tbody id="caseBody"><tr><td colspan="4" style="opacity:.7;">—</td></tr></tbody>
              </table>
            </div>
            <div id="caseDetail" style="margin-top:12px; font-size:12px; opacity:.9;"></div>
          </div>

          <div style="display:grid; gap:14px;">
            <div class="glass-panel" style="padding:16px; margin:0;">
              <div style="font-weight:700; margin-bottom:10px;">Users (Admin)</div>
              <div id="usersGate" style="font-size:12px; opacity:.8;">Admin only.</div>

              <div id="usersWrap" style="display:none;">
                <div style="display:flex; gap:10px; flex-wrap:wrap; margin-bottom:10px;">
                  <input id="newUsername" placeholder="Username" style="flex:1; min-width:140px; padding:10px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white;" />
                  <input id="newPassword" placeholder="Password" type="password" style="flex:1; min-width:140px; padding:10px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white;" />
                  <select id="newRole" style="padding:10px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white;">
                    <option value="operator">operator</option>
                    <option value="auditor">auditor</option>
                    <option value="admin">admin</option>
                  </select>
                  <button class="btn secondary" id="createUserBtn"><i class="ph-bold ph-user-plus"></i></button>
                </div>
                <div style="max-height: 240px; overflow:auto;">
                  <table class="data-table">
                    <thead><tr><th>User</th><th>Role</th><th>Status</th></tr></thead>
                    <tbody id="usersBody"><tr><td colspan="3" style="opacity:.7;">—</td></tr></tbody>
                  </table>
                </div>
              </div>
            </div>

            <div class="glass-panel" style="padding:16px; margin:0;">
              <div style="display:flex; align-items:center; justify-content:space-between; gap:10px;">
                <div style="font-weight:700;">Audit</div>
                <div style="display:flex; gap:10px; flex-wrap:wrap;">
                  <input id="auditActor" placeholder="Actor username" style="padding:10px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white; width: 140px;" />
                  <input id="auditType" placeholder="Event type" style="padding:10px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white; width: 140px;" />
                  <button class="btn secondary" id="auditLoadBtn"><i class="ph-bold ph-list-magnifying-glass"></i></button>
                </div>
              </div>
              <div style="max-height: 240px; overflow:auto; margin-top:10px;">
                <table class="data-table">
                  <thead><tr><th>Time</th><th>Event</th><th>Actor</th></tr></thead>
                  <tbody id="auditBody"><tr><td colspan="3" style="opacity:.7;">—</td></tr></tbody>
                </table>
              </div>
            </div>

            <div class="glass-panel" style="padding:16px; margin:0; display:none;" id="policyPanel">
              <div style="font-weight:700; margin-bottom:10px;">Policy (Active)</div>
              <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-bottom:10px;">
                <button class="btn secondary" id="policyLoadBtn"><i class="ph-bold ph-download"></i> Load</button>
                <button class="btn secondary" id="policySaveBtn"><i class="ph-bold ph-upload"></i> Activate</button>
              </div>
              <textarea id="policyJson" rows="6" style="width:100%; padding:12px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white; resize: vertical;" placeholder='{"expiry_required":false,"tracking_policy":"LOT_ONLY","missing_gs_behavior":"BLOCK","accept_numeric_as_gtin":true,"allow_commit_on_warn":true}'></textarea>
              <div style="font-size:12px; opacity:.8; margin-top:6px;">Admin only: POST <code>/api/policies/active</code></div>
            </div>
          </div>
        </div>
      </div>
    `;
    scroll.appendChild(staff);

    state.pagesReady = true;
  }

  // ---------------- Data rendering ----------------
  function renderOverview(ov) {
    // Stat cards
    const vals = $$(".stat-card .stat-val");
    if (vals.length >= 3) {
      vals[0].textContent = String(ov.daily_scans ?? 0);
      vals[1].textContent = `${Number(ov.success_rate ?? 0).toFixed(1)}%`;
      vals[2].textContent = String(ov.pending_issues ?? 0);
    }

    // Recent activity table (scan rows)
    const table = $(".data-table");
    const tbody = table ? $("tbody", table) : null;
    if (tbody) {
      tbody.innerHTML = "";
      const items = Array.isArray(ov.recent_scans) ? ov.recent_scans : [];
      if (!items.length) {
        tbody.innerHTML = `<tr><td colspan="4" style="opacity:.7;">No scans yet.</td></tr>`;
      } else {
        for (const r of items) {
          const decision = String(r.decision || "WARN").toUpperCase();
          const badgeCls = decision === "PASS" ? "success" : decision === "WARN" ? "warning" : "danger";
          const ai = r.normalized ? String(r.normalized).slice(0, 28) : String(r.raw_string || "").slice(0, 28);
          tbody.insertAdjacentHTML(
            "beforeend",
            `<tr>
              <td>${escapeHtml(r.scan_id)}</td>
              <td><span class="badge ${badgeCls}">${escapeHtml(decision)}</span></td>
              <td>${escapeHtml(ai)}${ai.length >= 28 ? "…" : ""}</td>
              <td>${escapeHtml(fmtDate(r.created_at))}</td>
            </tr>`
          );
        }
      }
    }

    // Throughput chart
    const c = el("chart-container");
    if (c) {
      c.innerHTML = "";
      const points = Array.isArray(ov.throughput) ? ov.throughput : [];
      const counts = points.map((p) => Number(p.count || 0));
      const max = Math.max(1, ...counts);
      const bars = counts.length ? counts : [0,0,0,0,0,0,0,0,0,0,0,0];
      bars.slice(-12).forEach((val) => {
        const bar = document.createElement("div");
        bar.style.cssText =
          "flex:1; background: var(--glass-border); border-radius: 6px; height: 0%; transition: height 800ms cubic-bezier(0.34, 1.56, 0.64, 1); cursor:pointer;";
        bar.onmouseenter = () => {
          if (window.sfx && window.sfx.hover) window.sfx.hover();
          bar.style.background = "var(--brand-primary)";
        };
        bar.onmouseleave = () => (bar.style.background = "var(--glass-border)");
        c.appendChild(bar);
        requestAnimationFrame(() => {
          const h = Math.round((val / max) * 100);
          bar.style.height = `${h}%`;
        });
      });
    }

    // Profile
    if (ov.me?.username) setUserProfile(ov.me.username, ov.me.role);
  }

  async function loadOverview() {
    const ov = await api("/api/ui/overview");
    if (ov && ov.ok) {
      state.user = ov.me;
      state.role = String(ov.me?.role || "").toLowerCase();
      renderOverview(ov);
      // keep commit scan id prefilled
      const commitScanId = $("#commitScanId");
      if (commitScanId && state.lastScan?.scan_id) commitScanId.value = state.lastScan.scan_id;
    }
    return ov;
  }

  // ---------------- Scanner ----------------
  async function initZXing() {
    if (state.zxingReady) return true;
    // Load ZXing UMD bundle if not already there
    if (window.ZXing) {
      state.zxingReady = true;
      return true;
    }
    // Try to load local copy first
    const candidates = ["/vendor/zxing-umd.min.js", "/zxing-umd.min.js", "https://unpkg.com/@zxing/library@0.20.0/umd/index.min.js"];
    for (const src of candidates) {
      try {
        await new Promise((resolve, reject) => {
          const s = document.createElement("script");
          s.src = src;
          s.onload = resolve;
          s.onerror = reject;
          document.head.appendChild(s);
        });
        if (window.ZXing) {
          state.zxingReady = true;
          return true;
        }
      } catch {
        // continue
      }
    }
    return false;
  }

  async function decodeOnce() {
    const vid = el("cameraFeed");
    const overlay = el("scanOverlay");
    if (!vid || !overlay) throw new Error("Scanner UI not found");

    overlay.style.display = "flex";

    // 1) Native BarcodeDetector (no external deps)
    if ("BarcodeDetector" in window) {
      let stream = null;
      try {
        const formats = ["qr_code", "code_128", "code_39", "ean_13", "ean_8", "upc_a", "upc_e", "itf", "data_matrix", "pdf417", "aztec"];
        const detector = new window.BarcodeDetector({ formats });

        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false });
        vid.srcObject = stream;
        await vid.play();

        return await new Promise((resolve, reject) => {
          const startedAt = Date.now();
          const timeoutMs = 25000;

          const tick = async () => {
            if (!vid || vid.readyState < 2) return requestAnimationFrame(tick);
            try {
              const codes = await detector.detect(vid);
              if (codes && codes.length) {
                const v = codes[0].rawValue || codes[0].data || "";
                resolve(String(v));
                return;
              }
              if (Date.now() - startedAt > timeoutMs) reject(new Error("Scan timeout"));
              else requestAnimationFrame(tick);
            } catch (e) {
              // Some implementations throw while warming up; keep trying briefly
              if (Date.now() - startedAt > timeoutMs) reject(e);
              else requestAnimationFrame(tick);
            }
          };

          tick();
        });
      } finally {
        try {
          if (stream) stream.getTracks().forEach((t) => t.stop());
        } catch {}
        try {
          vid.pause();
          vid.srcObject = null;
        } catch {}
        overlay.style.display = "none";
      }
    }

    // 2) ZXing fallback (loads from local candidate or CDN)
    const ok = await initZXing();
    if (!ok) {
      overlay.style.display = "none";
      throw new Error("No scanner available (BarcodeDetector/ZXing)");
    }

    const codeReader = new window.ZXing.BrowserMultiFormatReader();

    let deviceId = null;
    try {
      const devices = await window.ZXing.BrowserCodeReader.listVideoInputDevices();
      const back = devices.find((d) => /back|rear|environment/i.test(d.label));
      deviceId = (back || devices[0] || {}).deviceId || null;
    } catch {
      deviceId = null;
    }

    return new Promise((resolve, reject) => {
      const cleanup = async () => {
        try {
          await codeReader.reset();
        } catch {}
        overlay.style.display = "none";
      };

      codeReader.decodeFromVideoDevice(deviceId, vid, async (result, err) => {
        if (result) {
          await cleanup();
          resolve(result.getText());
        } else if (err && !(err instanceof window.ZXing.NotFoundException)) {
          await cleanup();
          reject(err);
        }
      });
    });
  }


  function setScannerStatus(text, variant = "idle") {
    const st = el("scannerStatus");
    if (!st) return;
    st.textContent = text;
    st.classList.remove("success", "warning", "danger");
    if (variant === "success") st.classList.add("success");
    if (variant === "warning") st.classList.add("warning");
    if (variant === "danger") st.classList.add("danger");
  }

  async function submitScan(raw) {
    const scan_id = `WOW-${Date.now()}-${String(Math.floor(Math.random() * 1e6)).padStart(6, "0")}`;
    const idem = uuid();
    const context = { template: "WOW", client_ts: new Date().toISOString(), ui: "WOW" };
    const payload = { scan_id, raw_string: raw, context };

    const resp = await api("/api/scans/parse-validate", {
      method: "POST",
      headers: { "Idempotency-Key": idem },
      body: payload,
    });

    state.lastScan = { scan_id, raw_string: raw, result: resp };

    // auto-create case for WARN/BLOCK (kept NO-BLOCK safe)
    const decision = String(resp.decision || "WARN").toUpperCase();
    if (decision === "WARN" || decision === "BLOCK") {
      try {
        await api("/api/cases", {
          method: "POST",
          body: {
            scan_id,
            raw_string: raw,
            decision,
            checks: Array.isArray(resp.checks) ? resp.checks : [],
            context,
          },
        });
      } catch {
        // ignore
      }
    }

    return resp;
  }

  async function doScanFlow() {
    if (state.scannerBusy) return;
    state.scannerBusy = true;

    try {
      setScannerStatus("Scanning…", "warning");
      if (window.sfx && window.sfx.play) window.sfx.play("scan_start");

      let raw = null;
      try {
        raw = await decodeOnce();
      } catch (e) {
        // fallback prompt
        raw = prompt("Camera not available. Paste barcode payload:", "") || "";
      }
      raw = String(raw || "").trim();
      if (!raw) throw new Error("Empty scan");

      setScannerStatus("Validating…", "warning");
      const resp = await submitScan(raw);

      const decision = String(resp.decision || "WARN").toUpperCase();
      const checks = Array.isArray(resp.checks) ? resp.checks : [];
      const top = checks[0]?.message || checks[0]?.code || "";

      if (decision === "PASS") {
        setScannerStatus("PASS", "success");
        if (window.sfx && window.sfx.play) window.sfx.play("success");
        toast("Scan accepted.", "success", { title: `PASS • ${resp.scan_id || state.lastScan.scan_id}` });
      } else if (decision === "WARN") {
        setScannerStatus("WARN", "warning");
        if (window.sfx && window.sfx.play) window.sfx.play("warn");
        toast(top || "Warnings detected.", "warn", {
          title: `WARN • ${resp.scan_id || state.lastScan.scan_id}`,
          ttl: 4200,
        });
      } else {
        setScannerStatus("BLOCK", "danger");
        if (window.sfx && window.sfx.play) window.sfx.play("error");
        toast(top || "Blocked (policy).", "error", { title: `BLOCK • ${resp.scan_id || state.lastScan.scan_id}`, ttl: 5200 });
      }

      // prefill commit scan id
      const commitScanId = $("#commitScanId");
      if (commitScanId) commitScanId.value = state.lastScan.scan_id;

      await loadOverview();
    } finally {
      state.scannerBusy = false;
      // restore after a bit
      setTimeout(() => {
        if (state.activeTab === "overview") setScannerStatus("Ready", "idle");
      }, 700);
    }
  }

  // ---------------- Inventory actions ----------------
  async function loadTop200(filter = "") {
    const body = el("invItemsBody");
    if (!body) return;
    body.innerHTML = `<tr><td colspan="2" style="opacity:.7;">Loading…</td></tr>`;
    const data = await api("/api/items-cache/top200");
    const items = data?.items || [];
    const q = String(filter || "").toLowerCase().trim();
    const filtered = q ? items.filter((x) => String(x.item_no).toLowerCase().includes(q) || String(x.item_name).toLowerCase().includes(q)) : items;

    if (!filtered.length) {
      body.innerHTML = `<tr><td colspan="2" style="opacity:.7;">No items.</td></tr>`;
      return;
    }
    body.innerHTML = "";
    for (const it of filtered.slice(0, 200)) {
      body.insertAdjacentHTML(
        "beforeend",
        `<tr><td>${escapeHtml(it.item_no)}</td><td>${escapeHtml(it.item_name)}</td></tr>`
      );
    }
  }

  async function adminSyncItems() {
    const r = await api("/api/items-cache/sync", { method: "POST", body: {} });
    toast(r.message || "Sync requested.", "info", { title: "Items Cache" });
  }

  async function operatorMapGTIN(gtin, itemNo) {
    const r = await api("/api/operator/map-gtin", { method: "POST", body: { gtin, item_no: itemNo } });
    toast(`Mapped GTIN → ${r.item_no} (${r.item_name || "OK"})`, "success", { title: "Mapping saved" });
    return r;
  }

  async function adminUpsertGTIN(gtin, itemNo) {
    const r = await api("/api/gtin-map/upsert", { method: "POST", body: { gtin, itemNo } });
    toast(`Upserted ${r.gtin} → ${r.item_no}`, "success", { title: "Admin upsert" });
    return r;
  }

  async function loadAdminMappings(search = "") {
    const body = el("mapBody");
    if (!body) return;
    body.innerHTML = `<tr><td colspan="3" style="opacity:.7;">Loading…</td></tr>`;
    const q = encodeURIComponent(search || "");
    const r = await api(`/api/gtin-map${q ? `?search=${q}` : ""}`);
    const items = r?.items || [];
    if (!items.length) {
      body.innerHTML = `<tr><td colspan="3" style="opacity:.7;">No mappings.</td></tr>`;
      return;
    }
    body.innerHTML = "";
    for (const m of items.slice(0, 200)) {
      body.insertAdjacentHTML(
        "beforeend",
        `<tr><td>${escapeHtml(m.gtin)}</td><td>${escapeHtml(m.item_no)}</td><td><span class="badge ${String(m.status||"ACTIVE")==="ACTIVE"?"success":"warning"}">${escapeHtml(m.status||"")}</span></td></tr>`
      );
    }
  }

  // ---------------- Commit actions ----------------
  async function commitPosting(scan_id, posting_intent) {
    const out = el("commitOut");
    if (out) out.textContent = "Submitting…";
    const idem = uuid();
    const r = await api("/api/postings/commit", {
      method: "POST",
      headers: { "Idempotency-Key": idem },
      body: { scan_id, posting_intent, context: { template: "WOW", client_ts: new Date().toISOString(), ui: "WOW" } },
    });

    const badge = el("commitModeBadge");
    if (badge) badge.textContent = String(r.mode || "SIMULATED").toUpperCase();

    const doc = r?.bc_result?.document_no || "—";
    const warnings = Array.isArray(r.warnings) ? r.warnings : [];
    const w = warnings.slice(0, 3).map((x) => x.message || x.code).filter(Boolean).join(" • ");

    if (out) {
      out.innerHTML = `<div><b>OK</b> • ${escapeHtml(r.posting_intent)} • Doc: <b>${escapeHtml(doc)}</b></div>
                       <div style="opacity:.85; margin-top:6px;">${warnings.length ? `Warnings: ${escapeHtml(w)}${warnings.length>3?" …":""}` : "No warnings."}</div>`;
    }
    toast(`Document ${doc}`, "success", { title: "Commit accepted" });
    return r;
  }

  async function legacyCommit(raw, commitType) {
    const out = el("legacyOut");
    if (out) out.textContent = "Submitting…";
    const r = await api("/api/commit", { method: "POST", body: { raw, commitType, template: "WOW", client_ts: new Date().toISOString() } });
    const doc = r?.bc_result?.document_no || "—";
    const warnings = Array.isArray(r.warnings) ? r.warnings : [];
    const w = warnings.slice(0, 3).map((x) => x.message || x.code).filter(Boolean).join(" • ");
    if (out) {
      out.innerHTML = `<div><b>OK</b> • ${escapeHtml(r.posting_intent)} • Doc: <b>${escapeHtml(doc)}</b></div>
                       <div style="opacity:.85; margin-top:6px;">${warnings.length ? `Warnings: ${escapeHtml(w)}${warnings.length>3?" …":""}` : "No warnings."}</div>`;
    }
    toast(`Legacy commit doc ${doc}`, "success", { title: "Commit (Legacy)" });
    return r;
  }

  // ---------------- Work sessions ----------------
  let wsSelected = null;
  async function loadWorkSessions(status = "") {
    const body = el("wsBody");
    if (!body) return;
    body.innerHTML = `<tr><td colspan="3" style="opacity:.7;">Loading…</td></tr>`;
    const q = status ? `?status=${encodeURIComponent(status)}` : "";
    const r = await api(`/api/work-sessions${q}`);
    const sessions = r?.sessions || [];
    if (!sessions.length) {
      body.innerHTML = `<tr><td colspan="3" style="opacity:.7;">No sessions.</td></tr>`;
      return;
    }
    body.innerHTML = "";
    sessions.forEach((s) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${escapeHtml(s.session_type)}</td><td><span class="badge ${s.status==="OPEN"?"success":"warning"}">${escapeHtml(s.status)}</span></td><td>${escapeHtml(s.reference_no || "")}</td>`;
      tr.style.cursor = "pointer";
      tr.addEventListener("click", () => {
        wsSelected = s.id;
        toast(`Selected session ${s.id}`, "info", { title: "Work Session", ttl: 1600 });
        loadWorkLines();
      });
      body.appendChild(tr);
    });
  }

  async function loadWorkLines() {
    const body = el("wsLinesBody");
    if (!body) return;
    if (!wsSelected) {
      body.innerHTML = `<tr><td colspan="4" style="opacity:.7;">Select a session…</td></tr>`;
      return;
    }
    body.innerHTML = `<tr><td colspan="4" style="opacity:.7;">Loading…</td></tr>`;
    const r = await api(`/api/work-sessions/${encodeURIComponent(wsSelected)}/lines`);
    const lines = r?.lines || [];
    if (!lines.length) {
      body.innerHTML = `<tr><td colspan="4" style="opacity:.7;">No lines.</td></tr>`;
      return;
    }
    body.innerHTML = "";
    for (const ln of lines) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${escapeHtml(ln.item_no)}<div style="font-size:11px; opacity:.7;">${escapeHtml(ln.item_name || "")}</div></td>
        <td>${escapeHtml(ln.expected_qty)}</td>
        <td>
          <input data-line="${escapeHtml(ln.id)}" value="${escapeHtml(ln.scanned_qty ?? 0)}" style="width:76px; padding:8px; border-radius:10px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white;" />
        </td>
        <td>${escapeHtml(ln.remaining_qty ?? "")}</td>
      `;
      body.appendChild(tr);
    }

    // bind inputs -> update scanned qty
    $$("input[data-line]", body).forEach((inp) => {
      inp.addEventListener("change", async () => {
        const lineId = inp.getAttribute("data-line");
        const v = Number(inp.value);
        if (!Number.isFinite(v) || v < 0) {
          toast("Invalid scanned qty", "error");
          return;
        }
        try {
          await api(`/api/work-sessions/${encodeURIComponent(wsSelected)}/lines/${encodeURIComponent(lineId)}`, {
            method: "PATCH",
            body: { scanned_qty: v },
          });
          toast("Line updated", "success", { ttl: 1400 });
          loadWorkLines();
        } catch (e) {
          toast(e.message || "Update failed", "error");
        }
      });
    });
  }

  async function createWorkSession() {
    const session_type = prompt("Session type (e.g., RECEIPT / TRANSFER / CYCLE_COUNT):", "RECEIPT");
    if (!session_type) return;
    const reference_no = prompt("Reference no (optional):", "") || null;
    const r = await api("/api/work-sessions", { method: "POST", body: { session_type, reference_no } });
    toast(`Created ${r.session?.id || ""}`, "success", { title: "Work Session" });
    await loadWorkSessions(el("wsStatus")?.value || "");
  }

  async function addWorkLines() {
    if (!wsSelected) return toast("Select a session first", "warn");
    const jsonText = prompt("Paste JSON array of lines: [{item_no:'1000', expected_qty:5}, ...]", "[]");
    if (!jsonText) return;
    let lines = null;
    try { lines = JSON.parse(jsonText); } catch { return toast("Invalid JSON", "error"); }
    const r = await api(`/api/work-sessions/${encodeURIComponent(wsSelected)}/lines`, { method: "POST", body: { lines } });
    toast(`Saved ${r.lines?.length || 0} lines`, "success", { title: "Work Lines" });
    loadWorkLines();
  }

  // ---------------- Cases / Audit / Users / Policy ----------------
  async function loadCases() {
    const body = el("caseBody");
    if (!body) return;

    const status = el("caseStatus")?.value || "";
    const decision = el("caseDecision")?.value || "";
    const qtext = el("caseSearch")?.value || "";

    const params = new URLSearchParams();
    if (status) params.set("status", status);
    if (decision) params.set("decision", decision);
    if (qtext) params.set("q", qtext);

    body.innerHTML = `<tr><td colspan="4" style="opacity:.7;">Loading…</td></tr>`;
    const r = await api(`/api/cases?${params.toString()}`);
    const rows = Array.isArray(r) ? r : [];
    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="4" style="opacity:.7;">No cases.</td></tr>`;
      return;
    }
    body.innerHTML = "";
    rows.forEach((c) => {
      const tr = document.createElement("tr");
      tr.style.cursor = "pointer";
      const dec = String(c.decision || "").toUpperCase();
      const bcls = dec === "WARN" ? "warning" : dec === "BLOCK" ? "danger" : "success";
      tr.innerHTML = `<td>${escapeHtml(c.id)}</td><td>${escapeHtml(c.status)}</td><td><span class="badge ${bcls}">${escapeHtml(dec)}</span></td><td>${escapeHtml(c.scan_id)}</td>`;
      tr.addEventListener("click", () => openCase(c.id));
      body.appendChild(tr);
    });
  }

  async function openCase(caseId) {
    const box = el("caseDetail");
    if (!box) return;

    const c = await api(`/api/cases/${encodeURIComponent(caseId)}`);
    const canEdit = state.role === "admin";

    const checks = (() => {
      try { return JSON.parse(c.checks || "[]"); } catch { return Array.isArray(c.checks) ? c.checks : []; }
    })();

    const top = checks.slice(0, 4).map((x) => x.message || x.code).filter(Boolean);

    box.innerHTML = `
      <div style="padding:12px; border-radius:14px; border:1px solid var(--glass-border); background:rgba(255,255,255,.04);">
        <div style="display:flex; justify-content:space-between; gap:10px; flex-wrap:wrap;">
          <div><b>${escapeHtml(c.id)}</b> • <span class="badge ${String(c.decision||"WARN")==="WARN"?"warning":"danger"}">${escapeHtml(String(c.decision||""))}</span></div>
          <div style="opacity:.8;">${escapeHtml(fmtDate(c.created_at))}</div>
        </div>
        <div style="margin-top:8px; opacity:.85;"><b>Scan:</b> ${escapeHtml(c.scan_id)} • <b>User:</b> ${escapeHtml(c.user_id)}</div>
        <div style="margin-top:8px; opacity:.85;"><b>Top checks:</b> ${escapeHtml(top.join(" • ") || "—")}</div>
        <div style="margin-top:10px; display:grid; gap:10px;">
          <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
            <label style="opacity:.8; font-size:12px;">Status</label>
            <select id="caseEditStatus" ${canEdit ? "" : "disabled"} style="padding:10px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white;">
              ${["NEW","IN_PROGRESS","RESOLVED","CLOSED"].map(s => `<option value="${s}" ${String(c.status)===s?"selected":""}>${s}</option>`).join("")}
            </select>
          </div>
          <textarea id="caseEditComment" ${canEdit ? "" : "disabled"} rows="2" style="width:100%; padding:10px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white; resize: vertical;" placeholder="Comment">${escapeHtml(c.comment || "")}</textarea>
          <textarea id="caseEditResolution" ${canEdit ? "" : "disabled"} rows="2" style="width:100%; padding:10px; border-radius:12px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white; resize: vertical;" placeholder="Resolution">${escapeHtml(c.resolution || "")}</textarea>
          <div style="display:flex; gap:10px; justify-content:flex-end; flex-wrap:wrap;">
            <button class="btn secondary" id="caseReloadBtn"><i class="ph-bold ph-arrow-clockwise"></i></button>
            <button class="btn primary" id="caseSaveBtn" style="display:${canEdit ? "inline-flex" : "none"};"><i class="ph-bold ph-check"></i> Save</button>
          </div>
        </div>
      </div>
    `;

    $("#caseReloadBtn", box)?.addEventListener("click", () => openCase(caseId));
    $("#caseSaveBtn", box)?.addEventListener("click", async () => {
      try {
        const status = el("caseEditStatus")?.value || c.status;
        const comment = el("caseEditComment")?.value || "";
        const resolution = el("caseEditResolution")?.value || "";
        await api(`/api/cases/${encodeURIComponent(caseId)}`, { method: "PATCH", body: { status, comment, resolution } });
        toast("Case updated", "success");
        loadCases();
        openCase(caseId);
      } catch (e) {
        toast(e.message || "Update failed", "error");
      }
    });
  }

  async function loadAudit() {
    const body = el("auditBody");
    if (!body) return;
    const actor = el("auditActor")?.value || "";
    const type = el("auditType")?.value || "";
    const params = new URLSearchParams();
    if (actor) params.set("actor_username", actor);
    if (type) params.set("event_type", type);

    body.innerHTML = `<tr><td colspan="3" style="opacity:.7;">Loading…</td></tr>`;
    try {
      const r = await api(`/api/audit?${params.toString()}`);
      const items = r?.items || [];
      if (!items.length) {
        body.innerHTML = `<tr><td colspan="3" style="opacity:.7;">No audit events.</td></tr>`;
        return;
      }
      body.innerHTML = "";
      items.slice(0, 200).forEach((a) => {
        body.insertAdjacentHTML(
          "beforeend",
          `<tr>
            <td>${escapeHtml(fmtDate(a.created_at))}</td>
            <td>${escapeHtml(a.event_type)}</td>
            <td>${escapeHtml(a.actor_username)}<div style="font-size:11px; opacity:.7;">${escapeHtml(a.actor_role || "")}</div></td>
          </tr>`
        );
      });
    } catch (e) {
      body.innerHTML = `<tr><td colspan="3" style="opacity:.7;">${escapeHtml(e.message || "Forbidden")}</td></tr>`;
    }
  }

  async function loadUsers() {
    const body = el("usersBody");
    if (!body) return;
    body.innerHTML = `<tr><td colspan="3" style="opacity:.7;">Loading…</td></tr>`;
    const r = await api("/api/users");
    const users = Array.isArray(r) ? r : [];
    if (!users.length) {
      body.innerHTML = `<tr><td colspan="3" style="opacity:.7;">No users.</td></tr>`;
      return;
    }
    body.innerHTML = "";
    users.forEach((u) => {
      const roleSel = `
        <select data-user="${escapeHtml(u.id)}" data-kind="role" style="padding:8px; border-radius:10px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white;">
          ${["operator","auditor","admin"].map(r => `<option value="${r}" ${u.role===r?"selected":""}>${r}</option>`).join("")}
        </select>
      `;
      const statusSel = `
        <select data-user="${escapeHtml(u.id)}" data-kind="active" style="padding:8px; border-radius:10px; border:1px solid var(--glass-border); background:rgba(255,255,255,.06); color:white;">
          <option value="true" ${u.status==="ACTIVE"?"selected":""}>ACTIVE</option>
          <option value="false" ${u.status!=="ACTIVE"?"selected":""}>DISABLED</option>
        </select>
      `;
      body.insertAdjacentHTML(
        "beforeend",
        `<tr>
          <td>${escapeHtml(u.username)}<div style="font-size:11px; opacity:.7;">${escapeHtml(fmtDate(u.created_at))}</div></td>
          <td>${roleSel}</td>
          <td>${statusSel}</td>
        </tr>`
      );
    });

    // bind updates
    $$("select[data-user]", body).forEach((sel) => {
      sel.addEventListener("change", async () => {
        const id = sel.getAttribute("data-user");
        const kind = sel.getAttribute("data-kind");
        const role = kind === "role" ? sel.value : null;
        const is_active = kind === "active" ? sel.value === "true" : null;
        try {
          await api(`/api/admin/users/${encodeURIComponent(id)}`, { method: "PATCH", body: { ...(role ? { role } : {}), ...(is_active !== null ? { is_active } : {}) } });
          toast("User updated", "success", { ttl: 1400 });
        } catch (e) {
          toast(e.message || "Update failed", "error");
        }
      });
    });
  }

  async function createUser() {
    const username = el("newUsername")?.value?.trim();
    const password = el("newPassword")?.value;
    const role = el("newRole")?.value;
    if (!username || !password || !role) return toast("Fill username, password, role", "warn");
    await api("/api/users", { method: "POST", body: { username, password, role } });
    el("newUsername").value = "";
    el("newPassword").value = "";
    toast("User created", "success");
    loadUsers();
  }

  async function loadPolicy() {
    const r = await api("/api/policies/active");
    const ta = el("policyJson");
    if (ta) ta.value = JSON.stringify(r.policy || {}, null, 2);
    toast("Policy loaded", "success", { ttl: 1400 });
  }

  async function savePolicy() {
    const ta = el("policyJson");
    if (!ta) return;
    let cfg = null;
    try { cfg = JSON.parse(ta.value); } catch { return toast("Invalid JSON", "error"); }
    const r = await api("/api/policies/active", { method: "POST", body: cfg });
    toast(`Policy activated v${r.version}`, "success");
  }

  // ---------------- Wiring ----------------
  function bindNav() {
    const nav = $$(".nav-item");
    // If WOW template changes, keep best-effort mapping by order
    nav.forEach((n, idx) => {
      n.addEventListener("click", (e) => {
        e.preventDefault();
        if (window.sfx && window.sfx.click) window.sfx.click();
        if (idx === 0) showTab("overview");
        if (idx === 1) showTab("inventory");
        if (idx === 2) showTab("shipments");
        if (idx === 3) showTab("staff");
      });
    });
  }

  function bindSearchPill() {
    const input = $(".search-pill input");
    if (!input) return;
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        // Context-aware search: Inventory -> mappings, Staff -> cases
        if (state.activeTab === "inventory") {
          const v = input.value;
          const mapSearch = el("mapSearch");
          if (mapSearch) { mapSearch.value = v; loadAdminMappings(v); }
          const invSearch = el("invItemSearch");
          if (invSearch) { invSearch.value = v; loadTop200(v); }
        } else if (state.activeTab === "staff") {
          const v = input.value;
          const cs = el("caseSearch");
          if (cs) { cs.value = v; loadCases(); }
        }
      }
    });
  }

  function overrideWOWHandlers() {
    // Kill WOW demo login handler by cloning the form
    const lf = el("loginForm");
    if (lf && lf.parentNode) {
      const clone = lf.cloneNode(true);
      lf.parentNode.replaceChild(clone, lf);
    }

    // Override global functions referenced by onclick attributes
    window.logout = async function () {
      try { if (window.sfx && window.sfx.click) window.sfx.click(); } catch {}
      setToken(null);
      state.user = null;
      state.role = null;
      showView("login");
      toast("Signed out", "info", { ttl: 1400, title: "Logout" });
    };

    window.triggerScan = function () {
      // If the UI defines a custom scan modal (public/index.html), use it.
      if (typeof window.__ATH_CUSTOM_TRIGGER_SCAN__ === "function") {
        return window.__ATH_CUSTOM_TRIGGER_SCAN__();
      }
      doScanFlow().catch((e) => toast(e.message || "Scan failed", "error"));
    };
  }

  async function bindLogin() {
    const form = el("loginForm");
    const btn = el("loginBtn");
    const errBox = el("loginInlineError");
    if (!form || !btn) return;

    const pickUserEl = () =>
      el("username") ||
      form.querySelector('input[name="username"]') ||
      form.querySelector('input[type="text"]') ||
      form.querySelector('input[placeholder*="Operator"]') ||
      form.querySelector("input");

    const pickPassEl = () =>
      el("password") ||
      form.querySelector('input[name="password"]') ||
      form.querySelector('input[type="password"]') ||
      form.querySelector('input[placeholder*="Access"]');

    const setLoginError = (msg) => {
      if (!errBox) return;
      errBox.textContent = msg || "";
      errBox.style.display = msg ? "block" : "none";
    };

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      try { if (window.sfx && window.sfx.click) window.sfx.click(); } catch {}

      setLoginError("");

      const uEl = pickUserEl();
      const pEl = pickPassEl();

      const username = uEl?.value?.trim();
      const password = pEl?.value;

      if (!username || !password) {
        toast("Enter username & password", "warn", { title: "Login" });
        setLoginError("Enter username & password.");
        return;
      }

      btn.disabled = true;
      const original = btn.innerHTML;
      btn.innerHTML = `<i class="ph-bold ph-spinner" style="animation: spin 1s infinite linear"></i> Authenticating...`;

      try {
        const r = await api("/api/auth/login", { method: "POST", body: { username, password } });
        setToken(r.token);
        state.user = r.user;
        state.role = String(r.user?.role || "").toLowerCase();

        ensurePages();
        bindNav();
        bindSearchPill();
        wirePanelsByRole();
        showView("dashboard");
        showTab("overview");
        setUserProfile(r.user.username, r.user.role);

        toast("Welcome back.", "success", { title: "Authenticated", ttl: 1800 });
        await loadOverview();

        // Preload panel datasets
        loadTop200("").catch(()=>{});
        loadWorkSessions("").catch(()=>{});
        loadCases().catch(()=>{});
        loadAudit().catch(()=>{});
        if (state.role === "admin") {
          loadAdminMappings("").catch(()=>{});
          loadUsers().catch(()=>{});
        }
      } catch (err) {
        console.error("[AUTH] login failed:", err);
        toast(err.message || "Login failed", "error", { title: "Authentication" });
        setLoginError(err.message || "Login failed.");
      } finally {
        btn.disabled = false;
        btn.innerHTML = original;
      }
    });
  }

  function wirePanelsByRole() {
    // Inventory
    const invSyncBtn = el("invSyncBtn");
    const mapAdminBtn = el("mapAdminBtn");
    const adminMapWrap = el("adminMapListWrap");
    if (state.role === "admin") {
      if (invSyncBtn) invSyncBtn.style.display = "";
      if (mapAdminBtn) mapAdminBtn.style.display = "";
      if (adminMapWrap) adminMapWrap.style.display = "";
    } else {
      if (invSyncBtn) invSyncBtn.style.display = "none";
      if (mapAdminBtn) mapAdminBtn.style.display = "none";
      if (adminMapWrap) adminMapWrap.style.display = "none";
    }

    // Shipments: Work Sessions create/add lines admin only
    if (state.role === "admin") {
      const wsCreateBtn = el("wsCreateBtn");
      const wsAddLinesBtn = el("wsAddLinesBtn");
      if (wsCreateBtn) wsCreateBtn.style.display = "";
      if (wsAddLinesBtn) wsAddLinesBtn.style.display = "";
    }

    // Staff: Users + Policy admin only; Audit admin/auditor
    const usersWrap = el("usersWrap");
    const usersGate = el("usersGate");
    const policyPanel = el("policyPanel");

    if (state.role === "admin") {
      if (usersGate) usersGate.style.display = "none";
      if (usersWrap) usersWrap.style.display = "";
      if (policyPanel) policyPanel.style.display = "";
    } else {
      if (usersGate) usersGate.style.display = "";
      if (usersWrap) usersWrap.style.display = "none";
      if (policyPanel) policyPanel.style.display = "none";
    }
  }

  function bindPanels() {
    // Overview refresh (no dedicated button; use periodic)
    // Inventory
    el("invRefreshBtn")?.addEventListener("click", () => loadTop200(el("invItemSearch")?.value || ""));
    el("invSyncBtn")?.addEventListener("click", () => adminSyncItems().catch((e) => toast(e.message, "error")));
    el("invItemSearch")?.addEventListener("input", (e) => loadTop200(e.target.value).catch(()=>{}));

    el("mapOperatorBtn")?.addEventListener("click", async () => {
      const gtin = el("mapGtin")?.value?.trim();
      const itemNo = el("mapItem")?.value?.trim();
      if (!gtin || !itemNo) return toast("Enter GTIN + Item No", "warn");
      try {
        await operatorMapGTIN(gtin, itemNo);
        if (state.role === "admin") loadAdminMappings(el("mapSearch")?.value || "");
      } catch (e) {
        toast(e.message || "Mapping failed", "error");
      }
    });
    el("mapAdminBtn")?.addEventListener("click", async () => {
      const gtin = el("mapGtin")?.value?.trim();
      const itemNo = el("mapItem")?.value?.trim();
      if (!gtin || !itemNo) return toast("Enter GTIN + Item No", "warn");
      try {
        await adminUpsertGTIN(gtin, itemNo);
        loadAdminMappings(el("mapSearch")?.value || "");
      } catch (e) {
        toast(e.message || "Upsert failed", "error");
      }
    });
    el("mapSearch")?.addEventListener("input", (e) => loadAdminMappings(e.target.value).catch(()=>{}));

    // Shipments
    el("shipRefreshBtn")?.addEventListener("click", () => { loadWorkSessions(el("wsStatus")?.value || ""); });
    el("commitPR")?.addEventListener("click", async () => {
      const scan_id = el("commitScanId")?.value?.trim();
      if (!scan_id) return toast("Enter scan id", "warn");
      try { await commitPosting(scan_id, "PURCHASE_RECEIPT"); } catch (e) { toast(e.message || "Commit failed", "error"); }
    });
    el("commitTR")?.addEventListener("click", async () => {
      const scan_id = el("commitScanId")?.value?.trim();
      if (!scan_id) return toast("Enter scan id", "warn");
      try { await commitPosting(scan_id, "TRANSFER_RECEIPT"); } catch (e) { toast(e.message || "Commit failed", "error"); }
    });
    el("legacyCommitBtn")?.addEventListener("click", async () => {
      const raw = el("legacyRaw")?.value?.trim();
      if (!raw) return toast("Paste raw barcode payload", "warn");
      const commitType = el("legacyType")?.value || "RECEIPT";
      try { await legacyCommit(raw, commitType); } catch (e) { toast(e.message || "Commit failed", "error"); }
    });

    el("wsLoadBtn")?.addEventListener("click", () => loadWorkSessions(el("wsStatus")?.value || ""));
    el("wsLinesBtn")?.addEventListener("click", () => loadWorkLines());
    el("wsCreateBtn")?.addEventListener("click", () => createWorkSession().catch((e) => toast(e.message, "error")));
    el("wsAddLinesBtn")?.addEventListener("click", () => addWorkLines().catch((e) => toast(e.message, "error")));

    // Staff
    el("staffRefreshBtn")?.addEventListener("click", () => { loadCases(); loadAudit(); if (state.role==="admin") loadUsers(); });
    el("caseStatus")?.addEventListener("change", () => loadCases());
    el("caseDecision")?.addEventListener("change", () => loadCases());
    el("caseSearch")?.addEventListener("input", () => loadCases());

    el("auditLoadBtn")?.addEventListener("click", () => loadAudit());

    el("createUserBtn")?.addEventListener("click", () => createUser().catch((e) => toast(e.message, "error")));

    el("policyLoadBtn")?.addEventListener("click", () => loadPolicy().catch((e) => toast(e.message, "error")));
    el("policySaveBtn")?.addEventListener("click", () => savePolicy().catch((e) => toast(e.message, "error")));
  }

  // ---------------- Boot ----------------
  async function bootstrap() {
    overrideWOWHandlers();
    ensurePages();
    bindNav();
    bindSearchPill();
    await bindLogin();

    // Bind dynamic panels after pages exist
    bindPanels();

    // Restore token if present
    const tok = localStorage.getItem(storageKey);
    if (tok) {
      setToken(tok);
      try {
        const me = await api("/api/auth/me");
        state.user = me.user;
        state.role = String(me.user?.role || "").toLowerCase();
        wirePanelsByRole();
        showView("dashboard");
        showTab("overview");
        setUserProfile(me.user.username, me.user.role);
        await loadOverview();

        // Preload panel datasets
        loadTop200("").catch(()=>{});
        loadWorkSessions("").catch(()=>{});
        loadCases().catch(()=>{});
        loadAudit().catch(()=>{});
        if (state.role === "admin") {
          loadAdminMappings("").catch(()=>{});
          loadUsers().catch(()=>{});
        }
      } catch {
        setToken(null);
        showView("login");
      }
    } else {
      showView("login");
    }

    // periodic refresh on overview
    setInterval(() => {
      if (state.token && state.activeTab === "overview") loadOverview().catch(()=>{});
    }, 15000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrap);
  } else {
    bootstrap();
  }
})();
