/* WOW UI (ATH) — Functional wiring to Backend + Database
   - Auth: POST /api/auth/login, GET /api/auth/me
   - Overview: GET /api/ui/overview (server helper)
   - Scan: POST /api/scans/parse-validate (+ optional POST /api/cases)
   - Commit: POST /api/postings/commit
   - Inventory: GET /api/items-cache/top200, POST /api/operator/map-gtin
   - Shipments: GET /api/work-sessions
   - Staff: GET /api/admin/users (admin only)
*/

(function () {
  'use strict';

  const el = (id) => document.getElementById(id);
  const qs = (sel, root = document) => root.querySelector(sel);
  const qsa = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const STORAGE = {
    token: 'ath.token',
    me: 'ath.me',
    theme: 'ath.theme',
  };

  const state = {
    token: localStorage.getItem(STORAGE.token) || '',
    me: safeJson(localStorage.getItem(STORAGE.me)) || null,
    theme: localStorage.getItem(STORAGE.theme) || (document.documentElement.getAttribute('data-theme') || 'dark'),
    scanning: false,
    stream: null,
    detector: null,
    scanTimer: null,
    lastScan: null,
  };

  // ---------------- Utilities ----------------
  function safeJson(s) {
    try { return JSON.parse(s || 'null'); } catch { return null; }
  }

  function uuid4() {
    const b = new Uint8Array(16);
    crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const hex = [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  function setText(id, value) {
    const n = el(id);
    if (n) n.textContent = value;
  }

  function fmtTs(ts) {
    try {
      const d = new Date(ts);
      return d.toLocaleString(undefined, { hour12: false });
    } catch { return String(ts || ''); }
  }

  function showToast(title, msg, type) {
    const area = el('toastArea');
    if (!area) return;

    const icon = type === 'warn'
      ? '<i class="ph-fill ph-warning" style="font-size: 20px; color: var(--tactical-amber)"></i>'
      : type === 'bad'
        ? '<i class="ph-fill ph-x-circle" style="font-size: 20px; color: var(--tactical-red)"></i>'
        : '<i class="ph-fill ph-check-circle" style="font-size: 20px; color: var(--tactical-green)"></i>';

    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `${icon}<div><div style="font-weight: 800; font-size: 14px;">${escapeHtml(title)}</div><div style="font-size: 12px; color: var(--text-muted);">${escapeHtml(msg)}</div></div>`;
    area.appendChild(toast);
    setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 250); }, 4200);
  }

  function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  async function api(path, { method = 'GET', json, headers } = {}) {
    const h = { ...(headers || {}) };
    if (state.token) h['Authorization'] = `Bearer ${state.token}`;
    if (json !== undefined) h['Content-Type'] = 'application/json';

    const r = await fetch(path, {
      method,
      headers: h,
      body: json !== undefined ? JSON.stringify(json) : undefined,
    });

    const ct = (r.headers.get('content-type') || '').toLowerCase();
    let payload = null;
    if (ct.includes('application/json')) payload = await r.json();
    else payload = await r.text();

    if (!r.ok) {
      const msg = (payload && payload.error) ? payload.error : (payload && payload.message) ? payload.message : (typeof payload === 'string' ? payload : 'REQUEST_FAILED');
      const err = new Error(msg);
      err.status = r.status;
      err.payload = payload;
      throw err;
    }
    return payload;
  }

  function clearSession() {
    state.token = '';
    state.me = null;
    localStorage.removeItem(STORAGE.token);
    localStorage.removeItem(STORAGE.me);
  }

  function setView(which) {
    const login = el('view-login');
    const dash = el('view-dashboard');
    if (!login || !dash) return;
    login.classList.toggle('active', which === 'login');
    dash.classList.toggle('active', which === 'dashboard');
  }

  function setProfile() {
    const name = state.me?.username || '—';
    const role = String(state.me?.role || '—').toUpperCase();
    setText('profileName', name);
    setText('profileRole', role);
    const av = el('profileAvatar');
    if (av) av.textContent = name ? name.slice(0, 1).toUpperCase() : 'A';

    // RBAC: hide staff nav for non-admin
    const staffNav = qs('.nav-item[data-view="staff"]');
    if (staffNav) staffNav.style.display = (role === 'ADMIN') ? '' : 'none';
  }

  function setActiveNav(view) {
    qsa('.nav-item[data-view]').forEach((n) => {
      n.classList.toggle('active', n.getAttribute('data-view') === view);
    });
    qsa('.content-view').forEach((c) => {
      c.classList.toggle('active', c.id === `content-${view}`);
    });
  }

  // ---------------- Theme / Logout / Scan (called from HTML) ----------------
  window.toggleTheme = function toggleTheme() {
    try { window.sfx?.click?.(); } catch {}
    const themes = ['dark', 'tactical', 'light'];
    const next = themes[(themes.indexOf(state.theme) + 1) % themes.length];
    state.theme = next;
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem(STORAGE.theme, next);
  };

  window.logout = function logout() {
    try { window.sfx?.click?.(); } catch {}
    stopCamera();
    closeScanModal();
    clearSession();
    setView('login');
    const btn = el('loginBtn');
    if (btn) btn.innerHTML = `<span>Initialize System</span><i class="ph-bold ph-arrow-right"></i>`;
    el('loginForm')?.reset();
  };

  window.triggerScan = async function triggerScan(force) {
    const desired = (typeof force === 'boolean') ? force : !state.scanning;
    state.scanning = desired;

    const scanner = el('globalScanner');
    const status = el('scannerStatus');
    const btn = qs('.scan-trigger-btn');

    if (state.scanning) {
      try { window.sfx?.play?.('scan_start'); } catch {}
      scanner?.classList.add('active');
      if (status) {
        status.innerText = 'ACTIVE CAPTURE';
        status.style.color = 'var(--tactical-red)';
      }
      if (btn) btn.innerHTML = `<i class="ph-bold ph-spinner" style="animation: spin 1s infinite linear"></i> STOP`;
      openScanModal();
      await startCamera();
    } else {
      try { window.sfx?.click?.(); } catch {}
      scanner?.classList.remove('active');
      if (status) {
        status.innerText = 'STANDBY';
        status.style.color = 'var(--brand-primary)';
      }
      if (btn) btn.innerHTML = `<i class="ph-bold ph-aperture"></i> SCAN`;
      stopCamera();
      closeScanModal();
    }
  };

  // ---------------- Login / Session ----------------
  async function ensureSession() {
    if (!state.token) return false;
    try {
      const me = await api('/api/auth/me');
      state.me = me?.user || null;
      localStorage.setItem(STORAGE.me, JSON.stringify(state.me || {}));
      return true;
    } catch {
      return false;
    }
  }

  async function doLogin(username, password) {
    const btn = el('loginBtn');
    if (btn) btn.innerHTML = `<i class="ph-bold ph-spinner" style="animation: spin 1s infinite linear"></i> Authenticating...`;
    const r = await api('/api/auth/login', { method: 'POST', json: { username, password } });
    state.token = r?.token || '';
    state.me = r?.user || null;
    if (!state.token) throw new Error('MISSING_TOKEN');
    localStorage.setItem(STORAGE.token, state.token);
    localStorage.setItem(STORAGE.me, JSON.stringify(state.me || {}));
  }

  // ---------------- Overview ----------------
  async function loadOverview() {
    try {
      const d = await api('/api/ui/overview');
      setText('statDailyScans', String(d.daily_scans ?? '—'));
      setText('statPendingIssues', String(d.pending_issues ?? '—'));
      setText('statSuccessRate', (d.success_rate ?? '—') === '—' ? '—' : `${d.success_rate}%`);

      // Chart
      renderChart(d.throughput || []);

      // Recent scans table
      const body = el('recentScansBody');
      if (body) {
        body.innerHTML = '';
        const rows = Array.isArray(d.recent_scans) ? d.recent_scans : [];
        rows.slice(0, 8).forEach((r) => {
          const tr = document.createElement('tr');
          tr.onmouseenter = () => { try { window.sfx?.hover?.(); } catch {} };

          const ref = (r.scan_id || '').slice(-12) || '—';
          const product = summarizeScan(r);
          const badge = decisionBadge(r.decision);

          tr.innerHTML = `
            <td style="font-family: 'JetBrains Mono'">${escapeHtml(ref)}</td>
            <td>${escapeHtml(product)}</td>
            <td>${badge}</td>
          `;
          body.appendChild(tr);
        });
      }
    } catch (e) {
      if (e.status === 401) return window.logout();
      showToast('Overview failed', e.message || 'ERROR', 'bad');
    }
  }

  function summarizeScan(r) {
    // Try to extract a short label from normalized raw
    const n = (r.normalized || r.raw_string || '').toString();
    if (!n) return '—';
    // Prefer GTIN part if exists
    const m = n.match(/\(01\)(\d{14})/);
    if (m) return `GTIN ${m[1]}`;
    return n.length > 28 ? `${n.slice(0, 28)}…` : n;
  }

  function decisionBadge(decision) {
    const d = String(decision || '').toUpperCase();
    if (d === 'PASS') return '<span class="badge success">Verified</span>';
    if (d === 'WARN') return '<span class="badge warn">Warn</span>';
    if (d === 'BLOCK') return '<span class="badge bad">Block</span>';
    return '<span class="badge">—</span>';
  }

  function renderChart(points) {
    const c = el('chart-container');
    if (!c) return;
    c.innerHTML = '';

    // points: [{ts, count}] for last 12h (server)
    const now = Date.now();
    const buckets = [];
    for (let i = 11; i >= 0; i--) {
      const t = new Date(now - i * 3600 * 1000);
      t.setMinutes(0, 0, 0);
      buckets.push({ t: t.getTime(), c: 0 });
    }
    (Array.isArray(points) ? points : []).forEach((p) => {
      const t = new Date(p.ts).getTime();
      const hr = new Date(t); hr.setMinutes(0, 0, 0);
      const key = hr.getTime();
      const b = buckets.find((x) => x.t === key);
      if (b) b.c = Number(p.count || 0);
    });
    const max = Math.max(1, ...buckets.map((b) => b.c));
    buckets.forEach((b, i) => {
      const bar = document.createElement('div');
      const h = Math.round((b.c / max) * 100);
      bar.style.cssText = `flex: 1; background: var(--glass-border); border-radius: 6px; height: 0%; transition: height 700ms cubic-bezier(0.34, 1.56, 0.64, 1); cursor: pointer;`;
      bar.title = `${new Date(b.t).getHours().toString().padStart(2,'0')}:00 — ${b.c}`;
      bar.onmouseenter = () => { try { window.sfx?.hover?.(); } catch {}; bar.style.background = 'var(--brand-primary)'; };
      bar.onmouseleave = () => { bar.style.background = 'var(--glass-border)'; };
      c.appendChild(bar);
      setTimeout(() => { bar.style.height = `${h}%`; }, 40 + i * 35);
    });
  }

  // ---------------- Inventory ----------------
  async function loadInventory() {
    try {
      const d = await api('/api/items-cache/top200');
      const body = el('top200Body');
      if (body) {
        body.innerHTML = '';
        (d.items || d || []).slice(0, 200).forEach((it) => {
          const tr = document.createElement('tr');
          tr.onmouseenter = () => { try { window.sfx?.hover?.(); } catch {} };
          tr.innerHTML = `<td style="font-family:'JetBrains Mono'">${escapeHtml(it.item_no || '')}</td><td>${escapeHtml(it.item_name || '')}</td>`;
          body.appendChild(tr);
        });
      }
    } catch (e) {
      if (e.status === 401) return window.logout();
      showToast('Inventory failed', e.message || 'ERROR', 'bad');
    }
  }

  async function mapGtin() {
    const gtin = (el('mapGtin')?.value || '').trim();
    const item_no = (el('mapItem')?.value || '').trim();
    if (!gtin || !item_no) {
      setText('mapResult', 'Enter GTIN + Item No');
      return;
    }
    try {
      const r = await api('/api/operator/map-gtin', { method: 'POST', json: { gtin, item_no } });
      setText('mapResult', r.ok ? `Mapped: ${r.gtin} → ${r.item_no}` : 'Mapping failed');
      try { window.sfx?.play?.('success'); } catch {}
      showToast('Mapped', `${r.gtin} → ${r.item_no}`, 'success');
    } catch (e) {
      setText('mapResult', e.message || 'ERROR');
      showToast('Map failed', e.message || 'ERROR', 'bad');
    }
  }

  // ---------------- Shipments ----------------
  async function loadShipments() {
    try {
      const d = await api('/api/work-sessions');
      const body = el('sessionsBody');
      if (body) {
        body.innerHTML = '';
        (d.sessions || d || []).slice(0, 60).forEach((s) => {
          const tr = document.createElement('tr');
          tr.onmouseenter = () => { try { window.sfx?.hover?.(); } catch {} };
          tr.innerHTML = `
            <td style="font-family:'JetBrains Mono'">${escapeHtml(String(s.id || '').slice(0, 8))}</td>
            <td>${escapeHtml(s.session_type || '')}</td>
            <td><span class="badge ${String(s.status).toUpperCase() === 'OPEN' ? 'warn' : 'success'}">${escapeHtml(s.status || '')}</span></td>
            <td>${escapeHtml(fmtTs(s.created_at))}</td>
          `;
          body.appendChild(tr);
        });
      }
    } catch (e) {
      if (e.status === 401) return window.logout();
      showToast('Shipments failed', e.message || 'ERROR', 'bad');
    }
  }

  // ---------------- Staff ----------------
  async function loadStaff() {
    const gate = el('staffGate');
    if (String(state.me?.role || '').toLowerCase() !== 'admin') {
      if (gate) gate.textContent = 'Admin only.';
      const body = el('usersBody');
      if (body) body.innerHTML = '';
      return;
    }
    if (gate) gate.textContent = '';
    try {
      const d = await api('/api/admin/users');
      const body = el('usersBody');
      if (body) {
        body.innerHTML = '';
        (d.users || []).forEach((u) => {
          const tr = document.createElement('tr');
          tr.onmouseenter = () => { try { window.sfx?.hover?.(); } catch {} };
          tr.innerHTML = `
            <td style="font-family:'JetBrains Mono'">${escapeHtml(u.username || '')}</td>
            <td>${escapeHtml(u.role || '')}</td>
            <td><span class="badge ${u.is_active ? 'success' : 'bad'}">${u.is_active ? 'Active' : 'Disabled'}</span></td>
            <td>${escapeHtml(fmtTs(u.created_at))}</td>
          `;
          body.appendChild(tr);
        });
      }
    } catch (e) {
      showToast('Staff failed', e.message || 'ERROR', 'bad');
    }
  }

  // ---------------- Scanner (camera + manual) ----------------
  function openScanModal() {
    const m = el('scanModal');
    if (m) m.classList.add('show');
    setText('scanHint', 'Camera capture');
    // unlock audio
    document.addEventListener('click', () => { try { window.sfx?.init?.(); } catch {} }, { once: true });
  }

  function closeScanModal() {
    const m = el('scanModal');
    if (m) m.classList.remove('show');
  }

  async function startCamera() {
    const video = el('scanVideo');
    if (!video) return;

    // If BarcodeDetector is available
    try {
      if ('BarcodeDetector' in window) {
        state.detector = new window.BarcodeDetector({ formats: ['qr_code', 'code_128', 'ean_13', 'ean_8', 'data_matrix', 'upc_a', 'upc_e'] });
      }
    } catch { state.detector = null; }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: 'environment' } },
        audio: false,
      });
      state.stream = stream;
      video.srcObject = stream;
      await video.play();
      if (!state.detector) {
        setText('scanHint', 'Camera ready (manual submit if your browser lacks BarcodeDetector)');
        return;
      }
      loopDetect();
    } catch (e) {
      setText('scanHint', 'Camera blocked. Use manual input.');
      showToast('Camera error', e.message || 'CAMERA_BLOCKED', 'warn');
    }
  }

  function loopDetect() {
    const video = el('scanVideo');
    if (!video || !state.detector || !state.scanning) return;

    state.scanTimer = window.setTimeout(async () => {
      try {
        const codes = await state.detector.detect(video);
        if (codes && codes.length) {
          const raw = codes[0].rawValue || '';
          if (raw) {
            await handleScanRaw(raw, { source: 'camera' });
            return;
          }
        }
      } catch {
        // ignore
      }
      loopDetect();
    }, 160);
  }

  function stopCamera() {
    if (state.scanTimer) {
      clearTimeout(state.scanTimer);
      state.scanTimer = null;
    }
    if (state.stream) {
      state.stream.getTracks().forEach((t) => t.stop());
      state.stream = null;
    }
    const v = el('scanVideo');
    if (v) v.srcObject = null;
  }

  async function handleScanRaw(raw, { source = 'manual' } = {}) {
    if (!raw) return;
    try {
      // Prevent double firing
      if (!state.scanning) return;
      state.scanning = false;

      // Stop scanner UI immediately
      await window.triggerScan(false);

      const scan_id = `SCAN-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
      const idem = uuid4();
      const context = {
        ui: 'WOW',
        source,
        user: state.me?.username,
        ts: new Date().toISOString(),
      };

      const pv = await api('/api/scans/parse-validate', {
        method: 'POST',
        headers: { 'Idempotency-Key': idem },
        json: { scan_id, raw_string: raw, context },
      });

      state.lastScan = pv;
      setText('lastResult', `${pv.decision}  •  ${summarizeScan(pv)}\n${scan_id}`);

      if (pv.decision === 'PASS') {
        try { window.sfx?.play?.('success'); } catch {}
        showToast('Scan Verified', summarizeScan(pv), 'success');
      } else {
        try { window.sfx?.play?.('warn'); } catch {}
        showToast('Scan Requires Review', `${pv.decision}: ${summarizeScan(pv)}`, 'warn');

        // Create a case automatically (WARN/BLOCK)
        try {
          await api('/api/cases', {
            method: 'POST',
            json: {
              scan_id: pv.scan_id,
              raw_string: raw,
              decision: pv.decision,
              checks: pv.checks || [],
              context: pv.context || context,
            },
          });
        } catch {
          // case creation best-effort
        }
      }

      // Refresh overview numbers
      loadOverview();
    } catch (e) {
      if (e.status === 401) return window.logout();
      showToast('Scan failed', e.message || 'ERROR', 'bad');
    }
  }

  // Commit posting using lastScan
  async function commit(intent) {
    const last = state.lastScan;
    if (!last?.scan_id) {
      showToast('Commit', 'No scan to commit.', 'warn');
      return;
    }
    try {
      const r = await api('/api/postings/commit', {
        method: 'POST',
        headers: { 'Idempotency-Key': uuid4() },
        json: { scan_id: last.scan_id, posting_intent: intent },
      });
      try { window.sfx?.play?.('success'); } catch {}
      showToast('Committed', `${intent}: ${r.bc_result?.status || 'OK'}`, 'success');
    } catch (e) {
      showToast('Commit failed', e.message || 'ERROR', 'bad');
    }
  }

  // ---------------- Bind ----------------
  function bind() {
    // Theme
    document.documentElement.setAttribute('data-theme', state.theme);

    // Login form
    el('loginForm')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      try { window.sfx?.click?.(); } catch {}
      const username = (el('loginUser')?.value || '').trim();
      const password = (el('loginPass')?.value || '').trim();
      try {
        await doLogin(username, password);
        setProfile();
        setView('dashboard');
        try { window.sfx?.play?.('success'); } catch {}
        showToast('Welcome Back', 'System Online.', 'success');
        setActiveNav('overview');
        loadOverview();
      } catch (e2) {
        showToast('Login failed', e2.message || 'ERROR', 'bad');
        const btn = el('loginBtn');
        if (btn) btn.innerHTML = `<span>Initialize System</span><i class="ph-bold ph-arrow-right"></i>`;
      }
    });

    // Nav
    qsa('.nav-item[data-view]').forEach((n) => {
      n.addEventListener('click', () => {
        const v = n.getAttribute('data-view') || 'overview';
        setActiveNav(v);
        if (v === 'overview') loadOverview();
        if (v === 'inventory') loadInventory();
        if (v === 'shipments') loadShipments();
        if (v === 'staff') loadStaff();
      });
    });

    // Modal
    el('btnCloseScan')?.addEventListener('click', () => window.triggerScan(false));
    el('btnManualSubmit')?.addEventListener('click', async () => {
      const raw = (el('scanManual')?.value || '').trim();
      if (!raw) return;
      // Start scan flow even if camera isn't scanning
      state.scanning = true;
      await handleScanRaw(raw, { source: 'manual' });
    });

    el('btnCommitPR')?.addEventListener('click', () => commit('PURCHASE_RECEIPT'));
    el('btnCommitTR')?.addEventListener('click', () => commit('TRANSFER_RECEIPT'));

    // Inventory controls
    el('btnRefreshInventory')?.addEventListener('click', loadInventory);
    el('btnMapGtin')?.addEventListener('click', mapGtin);

    // Shipments controls
    el('btnRefreshShipments')?.addEventListener('click', loadShipments);

    // Staff controls
    el('btnRefreshStaff')?.addEventListener('click', loadStaff);

    // Search pill shortcut
    el('globalSearch')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        setActiveNav('inventory');
        loadInventory();
        setTimeout(() => el('mapGtin')?.focus(), 150);
      }
    });
  }

  // ---------------- Boot ----------------
  document.addEventListener('DOMContentLoaded', async () => {
    bind();
    const ok = await ensureSession();
    if (ok) {
      setProfile();
      setView('dashboard');
      setActiveNav('overview');
      loadOverview();
    } else {
      clearSession();
      setView('login');
    }
  });
})();
