/* GS1/UDI Enterprise Hub — UI Rebuild (v3)
   - Static HTML/JS (no build) + PWA shell
   - Scanner: BarcodeDetector (preferred) with ZXing fallback (optional file: /vendor/zxing-umd.min.js)
   - Parsing: best-effort GS1 AI parsing in UI + optional remote parse/validate probing
   - API base can be set via:
       1) window.__API_BASE__ (injected by server)
       2) ?api=https://host (query param)
       3) same-origin default
*/
(() => {
  const BUILD = 'revamp-ui-2026-02-05-final';
  window.__BUILD__ = BUILD;

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  const state = {
    token: localStorage.getItem('gs1hub.token') || '',
    me: safeJson(localStorage.getItem('gs1hub.me')) || null,
    lang: localStorage.getItem('gs1hub.lang') || (document.documentElement.getAttribute('lang') || 'ar'),
    apiBase: resolveApiBase(),
    lastScan: null,
    queue: safeJson(localStorage.getItem('gs1hub.queue')) || [],
    scan: {
      running: false,
      engine: 'auto',
      detector: null,
      rafId: 0,
      stream: null,
      track: null,
      deviceIds: [],
      deviceIndex: 0,
      torchOn: false,
      zxing: { reader: null, controls: null },
      lastRaw: '',
      lastAt: 0,
    },
  };

  
  // ---- REVAMP UI helpers (v4)
  const I18N = {
    ar: {
      'nav.operator': 'المشغل',
      'nav.admin': 'الإدارة',
      'nav.docs': 'المستندات',
      'top.crumb': 'واجهة موحدة للمشغل والإدارة',
      'login.title': 'تسجيل الدخول',
      'login.credentials': 'بيانات الدخول',
      'operator.title': 'واجهة المشغل',
      'admin.title': 'لوحة الإدارة',
      'docs.title': 'المستندات',
      'crumb.login': 'تسجيل الدخول',
      'crumb.operator': 'واجهة المشغل',
      'crumb.admin': 'لوحة الإدارة',
      'crumb.docs': 'المستندات',
      'crumb.unauth': 'غير مصرح',
      'cmdk.placeholder': 'اكتب أمر… (Scan / Cases / Health)',
      'lang.button': 'EN',
    },
    en: {
      'nav.operator': 'Operator',
      'nav.admin': 'Admin',
      'nav.docs': 'Docs',
      'top.crumb': 'Unified Operator + Admin Console',
      'login.title': 'Sign in',
      'login.credentials': 'Credentials',
      'operator.title': 'Operator Console',
      'admin.title': 'Admin Console',
      'docs.title': 'Docs',
      'crumb.login': 'Sign in',
      'crumb.operator': 'Operator Console',
      'crumb.admin': 'Admin Console',
      'crumb.docs': 'Docs',
      'crumb.unauth': 'Access denied',
      'cmdk.placeholder': 'Type a command… (Scan / Cases / Health)',
      'lang.button': 'ع',
    },
  };

  function t(key) {
    const lang = state.lang || 'ar';
    return (I18N[lang] && I18N[lang][key]) || (I18N.ar && I18N.ar[key]) || key;
  }

  function applyLang(lang) {
    state.lang = (lang === 'en') ? 'en' : 'ar';
    try { localStorage.setItem('gs1hub.lang', state.lang); } catch {}
    document.documentElement.setAttribute('lang', state.lang);
    document.documentElement.setAttribute('dir', state.lang === 'en' ? 'ltr' : 'rtl');

    // swap text for tagged elements
    $$('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      if (!key) return;
      el.textContent = t(key);
    });

    const btn = $('#btnLang');
    if (btn) btn.textContent = t('lang.button');

    const cmdInput = $('#cmdkInput');
    if (cmdInput) cmdInput.setAttribute('placeholder', t('cmdk.placeholder'));
  }

  function initShell() {
    const shell = document.querySelector('.shell');
    if (!shell) return;
    const key = 'gs1hub.sidebar';
    const saved = localStorage.getItem(key) || '';
    if (saved === 'collapsed') shell.classList.add('sb-collapsed');

    const btn = $('#btnSidebar');
    if (btn) {
      btn.addEventListener('click', () => {
        shell.classList.toggle('sb-collapsed');
        try {
          localStorage.setItem(key, shell.classList.contains('sb-collapsed') ? 'collapsed' : 'expanded');
        } catch {}
      });
    }

    const langBtn = $('#btnLang');
    if (langBtn) {
      langBtn.addEventListener('click', () => applyLang(state.lang === 'ar' ? 'en' : 'ar'));
    }
  }

  // Modal
  function initModal() {
    const modal = $('#modal');
    if (!modal) return;

    function close() { modal.hidden = true; $('#modalBody') && ($('#modalBody').innerHTML = ''); }

    modal.addEventListener('click', (e) => {
      const t = e.target;
      if (t && t.getAttribute && t.getAttribute('data-close') === '1') close();
    });

    const closeBtn = $('#modalClose');
    if (closeBtn) closeBtn.addEventListener('click', close);

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !modal.hidden) close();
    });

    window.__showModal = (title, html) => {
      const mt = $('#modalTitle');
      const mb = $('#modalBody');
      if (mt) mt.textContent = title || '—';
      if (mb) mb.innerHTML = html || '';
      modal.hidden = false;
    };

    window.__closeModal = close;
  }

  // Command palette (Ctrl+K)
  function initCmdk() {
    const root = $('#cmdk');
    const input = $('#cmdkInput');
    const list = $('#cmdkList');
    const btn = $('#btnCmdk');
    if (!root || !input || !list) return;
    // Safety: never show the command palette by default
    root.hidden = true;

    const commands = [
      { name: () => (state.lang === 'ar' ? 'الانتقال: المشغل' : 'Go: Operator'), k: 'G O', run: () => (location.hash = '#/operator') },
      { name: () => (state.lang === 'ar' ? 'الانتقال: الإدارة' : 'Go: Admin'), k: 'G A', run: () => (location.hash = '#/admin') },
      { name: () => (state.lang === 'ar' ? 'الانتقال: المستندات' : 'Go: Docs'), k: 'G D', run: () => (location.hash = '#/docs') },
      { name: () => (state.lang === 'ar' ? 'فحص الاتصال (Health)' : 'Health check'), k: 'H', run: () => $('#btnHealth')?.click() },
      { name: () => (state.lang === 'ar' ? 'بدء المسح' : 'Start scan'), k: 'S', run: () => $('#btnStart')?.click() },
      { name: () => (state.lang === 'ar' ? 'إيقاف المسح' : 'Stop scan'), k: 'X', run: () => $('#btnStop')?.click() },
      { name: () => (state.lang === 'ar' ? 'تحديث الحالات' : 'Refresh cases'), k: 'R C', run: () => $('#btnRefreshCases')?.click() },
      { name: () => (state.lang === 'ar' ? 'تحديث اللوحة' : 'Refresh dashboard'), k: 'R D', run: () => $('#btnRefreshDash')?.click() },
    ];

    function close() {
      root.hidden = true;
      input.value = '';
      render('');
    }

    function open() {
      root.hidden = false;
      input.focus();
      input.select();
      render('');
    }

    function render(q) {
      const query = (q || '').trim().toLowerCase();
      const items = commands
        .map(c => ({ c, title: c.name() }))
        .filter(x => !query || x.title.toLowerCase().includes(query))
        .slice(0, 12);

      if (!items.length) {
        list.innerHTML = '<div class="muted" style="padding:12px; font-weight:900;">No matches</div>';
        return;
      }

      list.innerHTML = items.map((x, i) => `
        <div class="cmdk__item" data-idx="${i}">
          <div>${escapeHtml(x.title)}</div>
          <div class="cmdk__k">${escapeHtml(x.c.k || '')}</div>
        </div>
      `).join('');

      list.querySelectorAll('.cmdk__item').forEach(el => {
        el.addEventListener('click', () => {
          const idx = Number(el.getAttribute('data-idx') || '0');
          const cmd = items[idx]?.c;
          close();
          try { cmd && cmd.run(); } catch (e) {}
        });
      });

      // Enter runs first
      input.onkeydown = (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          const cmd = items[0]?.c;
          close();
          try { cmd && cmd.run(); } catch (e) {}
        }
        if (e.key === 'Escape') { e.preventDefault(); close(); }
      };
    }

    input.addEventListener('input', () => render(input.value));

    root.addEventListener('click', (e) => {
      // Click on backdrop closes (mobile friendly)
      if (e.target === root) return close();
      const t = e.target;
      if (t && t.getAttribute && t.getAttribute('data-close') === '1') close();
    });

    btn && btn.addEventListener('click', open);

    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && (e.key.toLowerCase() === 'k')) {
        e.preventDefault();
        root.hidden ? open() : close();
      }
      if (e.key === 'Escape' && !root.hidden) close();
    });
  }

  // Net status indicator
  function initNetPill() {
    const dot = $('#netDot');
    const text = $('#netText');
    const pill = $('#netPill');
    if (!dot || !text) return;

    function set(status) {
      dot.classList.remove('ok', 'bad');
      if (status === true) dot.classList.add('ok');
      else if (status === false) dot.classList.add('bad');
      text.textContent = 'API';
      if (pill) pill.title = status === true ? 'API: OK' : (status === false ? 'API: DOWN' : 'API: …');
    }

    async function ping() {
      try {
        await apiGet('/api/health');
        set(true);
      } catch (e) {
        set(false);
      }
    }

    set(null);
    setTimeout(ping, 650);
    setInterval(() => { if (!document.hidden) ping(); }, 45000);
  }


  // ---- Router
  const routes = {
    login: showLogin,
    operator: () => requireRole(['operator', 'admin', 'auditor'], showOperator),
    admin: () => requireRole(['admin', 'auditor'], showAdmin),
    docs: () => requireRole(['operator', 'admin', 'auditor'], showDocs),
    unauth: showUnauth,
  };

  
  async function hydrateAuth() {
    if (!state.token) return;
    try {
      const r = await apiGet('/api/auth/me');
      if (r && r.user) {
        state.me = r.user;
        localStorage.setItem('gs1hub.me', JSON.stringify(state.me || {}));
      }
    } catch (e) {
      // Token invalid/expired → logout safely
      state.token = '';
      state.me = null;
      localStorage.removeItem('gs1hub.token');
      localStorage.removeItem('gs1hub.me');
      updateSessionBox();
    }
  }

  function applyRBACNav() {
    const role = (state.me && state.me.role) || '';
    const adminLink = $$('[data-nav="admin"]')[0];
    if (adminLink) {
      const canSee = ['admin','auditor'].includes(role);
      adminLink.style.display = canSee ? '' : 'none';
    }
  }

  function defaultRoute() {
    const role = (state.me && state.me.role) || '';
    if (['admin','auditor'].includes(role)) return 'admin';
    return 'operator';
  }

async function boot() {
    $('#envHint').textContent = `API=${state.apiBase || '(same-origin)'} • build=${BUILD}`;

    // v4 shell UX
    initShell();
    initModal();
    initCmdk();
    initNetPill();
    applyLang(state.lang);

    await hydrateAuth();
    applyRBACNav();
    updateSessionBox();
    bindAuth();

    // Start from login screen for presentation/demo clarity.
    // (If a valid session exists, the login screen will show a "متابعة" button.)
    const initial = (location.hash.replace('#/', '') || '').trim().toLowerCase();
    if (initial && initial !== 'login') {
      location.hash = '#/login';
    }

    bindOperator();
    bindAdmin();
    bindDocs();
    registerSW();
    navigate();
    window.addEventListener('hashchange', navigate);
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) stopScan('hidden');
    });
  }

  function navigate() {
    const page = (location.hash.replace('#/', '') || '').trim();
    const target = page || 'login';

    // If user lands on any protected route (or /unauth) without a session, show login.
    if (!state.token && target !== 'login') {
      location.hash = '#/login';
      showLogin();
      return;
    }

    // Leaving operator? stop camera.
    const current = $$('.page').find(p => !p.hidden)?.dataset?.page;
    if (current === 'operator' && target !== 'operator') stopScan('nav');

    setActiveNav(target);
    if (routes[target]) routes[target]();
    else routes.login();
  }

  function showPage(name) {
    $$('.page').forEach(p => (p.hidden = p.dataset.page !== name));
    try { document.body.dataset.page = name; } catch {}
    try { document.body.dataset.auth = state.token ? '1' : '0'; } catch {}
    const crumb = $('#pageCrumb');
    if (crumb) {
      const map = {
        login: t('crumb.login'),
        operator: t('crumb.operator'),
        admin: t('crumb.admin'),
        docs: t('crumb.docs'),
        unauth: t('crumb.unauth'),
      };
      crumb.textContent = map[name] || 'GS1/UDI Enterprise Hub';
    }
  }

  function setActiveNav(name) {
    $$('[data-nav]').forEach(a => a.classList.toggle('is-active', a.dataset.nav === name));
  }

  // ---- Auth / RBAC
  function showLogin() {
    showPage('login');
    $('#btnLogout').hidden = true;
    updateSessionBox();
  }

  function showUnauth() {
    // If there is no session at all, do not show an "unauthorized" wall.
    // Always send users to the login screen for a predictable first-load UX.
    if (!state.token) {
      location.hash = '#/login';
      showLogin();
      return;
    }
    showPage('unauth');
    $('#btnLogout').hidden = true;
  }

  function showOperator() {
    showPage('operator');
    $('#btnLogout').hidden = false;
    $('#authBadge').textContent = roleLabel();
    renderFields({});
    renderQueue();
    updateScanButtons();
  }

  function showAdmin() {
    showPage('admin');
    $('#btnLogout').hidden = false;

    // If auditor (read-only), disable user creation controls
    const role = (state.me && state.me.role) || '';
    const canCreateUsers = role === 'admin';
    ['newUser','newPass','newRole','btnCreateUser'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.disabled = !canCreateUsers;
    });

    refreshDashboard().catch(() => {});
    refreshCases().catch(() => {});
    refreshUsers().catch(() => {});
  }

  function showDocs() {
    showPage('docs');
    $('#btnLogout').hidden = false;
  }

  function requireRole(allowed, ok) {
    const role = (state.me && state.me.role) || '';
    // No session → always send to login (not an "unauth" wall)
    if (!state.token) {
      location.hash = '#/login';
      showLogin();
      return;
    }
    // Session exists but role is insufficient → show unauth
    if (!allowed.includes(role)) {
      location.hash = '#/unauth';
      showUnauth();
      return;
    }
    ok();
  }

  function roleLabel() {
    // Keep the header clean: show username only (role remains in other areas).
    const role = (state.me && state.me.role) || '';
    const user = (state.me && state.me.username) || '';
    const u = String(user || '').trim();
    const r = String(role || '').trim();
    if (u) return u;
    if (r) return r;
    return '—';
  }


  function updateSessionBox() {
    const box = $('#sessionBox');
    const label = $('#sessionLabel');
    const btnC = $('#btnContinue');
    const btnX = $('#btnClearSession');
    if (!box || !label) return;

    const role = (state.me && state.me.role) || '';
    const user = (state.me && state.me.username) || '';
    const hasSession = !!(state.token && role && user);

    if (!hasSession) {
      box.hidden = true;
      const tb = $('#tbUser');
      if (tb) tb.hidden = true;
      return;
    }

    label.textContent = roleLabel();
    box.hidden = false;

    const tb = $('#tbUser');
    const tbt = $('#tbUserText');
    if (tb && tbt) {
      tb.hidden = false;
      tbt.textContent = roleLabel();
    }

    // Safety: if buttons exist but weren't bound yet, keep them enabled
    if (btnC) btnC.disabled = false;
    if (btnX) btnX.disabled = false;
  }


  function bindAuth() {
    $('#btnGoLogin')?.addEventListener('click', () => (location.hash = '#/login'));


    $('#btnContinue')?.addEventListener('click', () => {
      // Continue with existing valid session
      location.hash = '#/' + defaultRoute();
    });

    $('#btnClearSession')?.addEventListener('click', () => {
      stopScan('clear-session');
      state.token = '';
      state.me = null;
      localStorage.removeItem('gs1hub.token');
      localStorage.removeItem('gs1hub.me');
      applyRBACNav();
      updateSessionBox();
      try { document.body.dataset.auth = '0'; } catch {}
      location.hash = '#/login';
    });

    $('#btnLogout')?.addEventListener('click', () => {
      stopScan('logout');
      state.token = '';
      state.me = null;
      localStorage.removeItem('gs1hub.token');
      localStorage.removeItem('gs1hub.me');
      applyRBACNav();
      updateSessionBox();
      try { document.body.dataset.auth = '0'; } catch {}
      location.hash = '#/login';
    });

    $('#btnHealth')?.addEventListener('click', async () => {
      try {
        await apiGet('/api/health');
        toast('Health OK', 'ok');
      } catch (e) {
        toast('Health failed: ' + String(e.message || e), 'bad');
      }
    });

    $('#btnDemo')?.addEventListener('click', () => {
      $('#loginUser').value = 'operator';
      $('#loginPass').value = 'operator';
    });

    $('#loginForm')?.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      setAlert('#loginAlert', null);
      $('#btnLogin').disabled = true;
      try {
        const username = $('#loginUser').value.trim();
        const password = $('#loginPass').value;
        const res = await apiPost('/api/auth/login', { username, password });

        if (!res || !res.token) throw new Error('Missing token from /api/auth/login');
        state.token = res.token;
        state.me = res.user || null;

        localStorage.setItem('gs1hub.token', state.token);
        localStorage.setItem('gs1hub.me', JSON.stringify(state.me || {}));

        toast('تم تسجيل الدخول', 'ok');
        try { window.SFX?.success?.(); } catch {}
        applyRBACNav();
        updateSessionBox();
        location.hash = '#/' + defaultRoute();
      } catch (e) {
        try { window.SFX?.error?.(); } catch {}
        setAlert('#loginAlert', e.message || String(e), 'bad');
      } finally {
        $('#btnLogin').disabled = false;
      }
    });
  }

  // ---- Operator
  function bindOperator() {
    $('#btnCopyJson')?.addEventListener('click', async () => {
      const payload = buildCommitPayload();
      await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
      toast('تم النسخ', 'ok');
    });

    $('#btnRescan')?.addEventListener('click', () => {
      state.lastScan = null;
      $('#rawLast').textContent = '—';
      setStatus('—', 'neutral');
      renderFields({});
      $('#commitOut').textContent = 'ابدأ المسح أولاً.';
    });

    $('#btnCreateCase')?.addEventListener('click', async () => {
      try {
        const payload = {
          raw: (state.lastScan && state.lastScan.raw) || '',
          parsed: (state.lastScan && state.lastScan.parsed) || {},
          reason: 'OPERATOR_ESCALATION',
        };
        const res = await apiPost('/api/cases', payload);
        toast('تم إنشاء Case', 'ok');
        $('#commitOut').textContent = JSON.stringify(res, null, 2);
      } catch (e) {
        toast('فشل إنشاء Case: ' + (e.message || e), 'bad');
      }
    });

    $('#btnCommitReceipt')?.addEventListener('click', () => commit('RECEIPT'));
    $('#btnCommitTransfer')?.addEventListener('click', () => commit('TRANSFER'));

    $('#btnUpsertMap')?.addEventListener('click', async () => {
      setAlert('#mapAlert', null);
      try {
        const gtin = $('#gtinInput').value.trim();
        const itemNo = $('#itemInput').value.trim();
        if (!gtin || !itemNo) throw new Error('GTIN و Item No مطلوبين');
        const res = await apiPost('/api/gtin-map/upsert', { gtin, itemNo });
        setAlert('#mapAlert', 'تم الحفظ', 'ok');
        $('#commitOut').textContent = JSON.stringify(res, null, 2);
      } catch (e) {
        setAlert('#mapAlert', e.message || String(e), 'bad');
      }
    });

    $('#btnSync')?.addEventListener('click', async () => {
      await syncQueue();
    });

    // Scanner controls
    $('#btnStart')?.addEventListener('click', async () => {
      try {
        await startScan();
      } catch (e) {
        toast(e.message || String(e), 'bad');
      }
    });

    $('#btnStop')?.addEventListener('click', () => stopScan('user'));
    $('#btnTorch')?.addEventListener('click', () => toggleTorch());
    $('#btnSwap')?.addEventListener('click', () => swapCamera());
  }

  function updateScanButtons() {
    const running = state.scan.running;
    $('#btnStart').disabled = running;
    $('#btnStop').disabled = !running;
    $('#btnTorch').disabled = !running || !state.scan.track;
    $('#btnSwap').disabled = !running || (state.scan.deviceIds.length < 2);
    $('#btnTorch').textContent = state.scan.torchOn ? 'فلاش: ON' : 'فلاش';
  }

  async function startScan() {
    if (!state.token) throw new Error('سجّل الدخول أولاً');
    if (state.scan.running) return;

    
    try { window.SFX?.scanStart?.(); } catch {}
state.scan.engine = ($('#engineSelect')?.value || 'auto').toLowerCase();
    await ensureCameraList();

    const preferBD = canBarcodeDetector();
    const wantsZX = state.scan.engine === 'zxing';
    const wantsBD = state.scan.engine === 'bd';

    if ((wantsBD || (state.scan.engine === 'auto' && preferBD)) && canBarcodeDetector()) {
      await startBarcodeDetectorEngine();
      toast('BarcodeDetector: تشغيل', 'ok');
      return;
    }

    if (!wantsBD) {
      await startZXingEngine();
      toast('ZXing: تشغيل', 'ok');
      return;
    }

    throw new Error('لا يوجد Engine متاح. استخدم Chrome/Edge (BarcodeDetector) أو وفّر ZXing عبر /vendor/zxing-umd.min.js');
  }

  function stopScan(reason) {
    if (!state.scan.running && !state.scan.stream && !state.scan.zxing.reader) return;

    state.scan.running = false;
    if (state.scan.rafId) cancelAnimationFrame(state.scan.rafId);
    state.scan.rafId = 0;

    // ZXing cleanup
    try { state.scan.zxing.controls?.stop?.(); } catch {}
    try { state.scan.zxing.reader?.reset?.(); } catch {}
    state.scan.zxing.controls = null;
    state.scan.zxing.reader = null;

    // BarcodeDetector cleanup
    state.scan.detector = null;

    // Camera stream cleanup
    if (state.scan.stream) {
      try { state.scan.stream.getTracks().forEach(t => t.stop()); } catch {}
    }
    state.scan.stream = null;
    state.scan.track = null;
    state.scan.torchOn = false;

    const v = $('#video');
    if (v) {
      try { v.pause(); } catch {}
      v.srcObject = null;
    }

    updateScanButtons();
    if (reason && reason !== 'nav') console.log('scan stopped:', reason);
  }

  function canBarcodeDetector() {
    return typeof window.BarcodeDetector === 'function';
  }

  async function ensureCameraList() {
    if (!navigator.mediaDevices?.enumerateDevices) return;
    const devs = await navigator.mediaDevices.enumerateDevices();
    state.scan.deviceIds = devs.filter(d => d.kind === 'videoinput').map(d => d.deviceId);
    if (state.scan.deviceIndex >= state.scan.deviceIds.length) state.scan.deviceIndex = 0;
  }

  async function getStreamForCurrentDevice() {
    const deviceId = state.scan.deviceIds[state.scan.deviceIndex];
    const constraints = {
      audio: false,
      video: deviceId
        ? { deviceId: { exact: deviceId }, width: { ideal: 1280 }, height: { ideal: 720 } }
        : { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } },
    };
    return await navigator.mediaDevices.getUserMedia(constraints);
  }

  async function startBarcodeDetectorEngine() {
    stopScan('restart');
    state.scan.running = true;

    const v = $('#video');
    if (!v) throw new Error('Video element missing');

    let formats = ['data_matrix', 'code_128', 'ean_13', 'ean_8', 'upc_a', 'upc_e', 'qr_code', 'itf'];
    try {
      const supported = await BarcodeDetector.getSupportedFormats();
      formats = formats.filter(f => supported.includes(f));
    } catch {}

    state.scan.detector = new BarcodeDetector({ formats });
    state.scan.stream = await getStreamForCurrentDevice();
    v.srcObject = state.scan.stream;
    await v.play();
    state.scan.track = state.scan.stream.getVideoTracks()[0] || null;

    updateScanButtons();
    loopBarcodeDetector(v);
  }

  async function loopBarcodeDetector(videoEl) {
    if (!state.scan.running || !state.scan.detector) return;
    try {
      const codes = await state.scan.detector.detect(videoEl);
      if (codes?.length) {
        const raw = codes[0].rawValue || '';
        if (raw) await onDecoded(raw);
      }
    } catch {}
    state.scan.rafId = requestAnimationFrame(() => loopBarcodeDetector(videoEl));
  }

  async function startZXingEngine() {
    stopScan('restart');
    state.scan.running = true;

    let Z = window.ZXingBrowser || window.ZXing;
    // Try to load ZXing on-demand from same-origin vendor endpoint.
    if (!Z && typeof window.__ensureZXing === 'function') {
      try { window.__ensureZXing(); } catch {}
    }
    // If ZXing is being loaded via the local loader, wait for it.
    if (!Z && window.__ZXING_LOADING__ && typeof window.__ZXING_LOADING__.then === 'function') {
      try { await window.__ZXING_LOADING__; } catch {}
      Z = window.ZXingBrowser || window.ZXing;
    }
    if (!Z) throw new Error('ZXing غير متاح حالياً. تأكد أن السيرفر يقدّم: /vendor/zxing-umd.min.js (Same-Origin). إذا المتصفح يدعم BarcodeDetector فسيعمل بدون ZXing.');

    const v = $('#video');
    if (!v) throw new Error('Video element missing');

    const ReaderCtor =
      Z.BrowserMultiFormatReader ||
      Z.BrowserMultiFormatContinuousReader ||
      Z.BrowserQRCodeReader ||
      null;

    if (!ReaderCtor) throw new Error('ZXing bundle غير متوافق');

    const reader = new ReaderCtor();
    state.scan.zxing.reader = reader;

    await ensureCameraList();
    const deviceId = state.scan.deviceIds[state.scan.deviceIndex] || null;

    updateScanButtons();

    const controls = await reader.decodeFromVideoDevice(deviceId, v, (result) => {
      if (result) {
        const txt = typeof result.getText === 'function' ? result.getText() : (result.text || result.rawValue || String(result));
        onDecoded(txt);
      }
    });

    state.scan.zxing.controls = controls || null;

    try {
      const stream = v.srcObject;
      if (stream?.getVideoTracks) state.scan.track = stream.getVideoTracks()[0] || null;
    } catch {}

    updateScanButtons();
  }

  async function swapCamera() {
    if (!state.scan.running) return;
    if (state.scan.deviceIds.length < 2) return;

    state.scan.deviceIndex = (state.scan.deviceIndex + 1) % state.scan.deviceIds.length;

    const engine = state.scan.engine;
    if (engine === 'zxing') await startZXingEngine();
    else await startBarcodeDetectorEngine();

    toast('تم تبديل الكاميرا', 'ok');
  }

  async function toggleTorch() {
    const t = state.scan.track;
    if (!t) return toast('الفلاش غير متاح في هذا الوضع', 'warn');

    const caps = t.getCapabilities ? t.getCapabilities() : {};
    if (!caps.torch) return toast('الجهاز لا يدعم Torch', 'warn');

    state.scan.torchOn = !state.scan.torchOn;
    try {
      await t.applyConstraints({ advanced: [{ torch: state.scan.torchOn }] });
      updateScanButtons();
    } catch {
      state.scan.torchOn = false;
      updateScanButtons();
      toast('فشل تشغيل الفلاش', 'bad');
    }
  }

  async function onDecoded(raw) {
    const now = Date.now();
    const clean = String(raw || '').trim();
    if (!clean) return;

    if (clean === state.scan.lastRaw && (now - state.scan.lastAt) < 1200) return;
    state.scan.lastRaw = clean;
    state.scan.lastAt = now;

    $('#rawLast').textContent = clean;
    setStatus('…', 'neutral');

    let parsed = null;
    let decision = null;

    const remote = await tryRemoteParseValidate(clean);
    if (remote) {
      parsed = remote.parsed || remote.data || remote.result?.parsed || remote.payload?.parsed || null;
      decision = remote.decision || remote.status || remote.result?.decision || remote.verdict || null;
    }

    if (!parsed) parsed = parseGS1(clean);
    if (!decision) decision = localDecision(parsed);

    applyScan({ raw: clean, parsed, status: String(decision).toUpperCase() });
  }

  function applyScan({ raw, parsed, status }) {
    // NO-BLOCK: normalize any BLOCK -> WARN
    let _status = String(status || '').toUpperCase();
    if (_status === 'BLOCK') _status = 'WARN';
    state.lastScan = { raw, parsed, status: _status };
    setStatus(_status, _status.toLowerCase());
    
    try {
      const s = _status;
      if (s === 'PASS' || s === 'OK') window.SFX?.success?.();
      else if (s === 'WARN') window.SFX?.warn?.();
      else window.SFX?.error?.();
    } catch {}
renderFields(parsed || {});
    renderWarnings(parsed || {}, _status);
    $('#commitOut').textContent = JSON.stringify({ status, parsed }, null, 2);
  }

  function setStatus(label, variant) {
    const el = $('#statusPill');
    const map = { pass: 'ok', warn: 'warn', block: 'bad', neutral: 'neutral' };
    const v = map[variant] || 'neutral';
    let cls = 'pill';
    if (v === 'ok') cls += ' pill--ok';
    if (v === 'warn') cls += ' pill--warn';
    if (v === 'bad') cls += ' pill--bad';
    el.innerHTML = `<span class="${cls}">${escapeHtml(label)}</span>`;
  }

  function renderFields(parsed) {
    const grid = $('#fieldsGrid');
    if (!grid) return;

    const ai = parsed.ai && typeof parsed.ai === 'object' ? parsed.ai : {};
    const core = {
      GTIN: parsed.gtin || ai['01'],
      LOT: parsed.lot || ai['10'],
      EXP: parsed.expiry || ai['17'],
      SERIAL: parsed.serial || ai['21'],
      QTY: parsed.qty || ai['30'] || ai['37'],
      UDI: parsed.udi || '',
    };

    const extraPairs = Object.entries(ai)
      .filter(([k]) => !['01', '10', '17', '21', '30', '37'].includes(k))
      .slice(0, 18);

    const items = [
      ...Object.entries(core),
      ...extraPairs.map(([k, v]) => [`AI ${k}`, v]),
    ];

    grid.innerHTML = items
      .map(([k, v]) => `
      <div class="kv">
        <div class="kv__k">${escapeHtml(k)}</div>
        <div class="kv__v mono">${escapeHtml(v || '—')}</div>
      </div>
    `).join('');
  }

  function computeWarnReasons(parsed) {
    const ai = parsed.ai && typeof parsed.ai === 'object' ? parsed.ai : {};
    const reasons = [];
    const gtin = parsed.gtin || ai['01'] || '';
    if (!gtin || String(gtin).length < 14) reasons.push('GTIN غير مكتمل أو غير موجود');
    const lot = parsed.lot || ai['10'] || '';
    if (!lot) reasons.push('LOT غير موجود');
    const expIso = parsed.expiry_iso || '';
    const exp = expIso || parsed.expiry || ai['17'] || '';
    if (exp) {
      // try ISO first
      const d = expIso ? new Date(expIso + 'T00:00:00Z') : new Date(exp);
      if (isNaN(d.valueOf())) {
        reasons.push('تاريخ الانتهاء غير قابل للقراءة');
      } else {
        const days = Math.floor((d - new Date()) / (1000*60*60*24));
        if (days < 0) reasons.push('المنتج منتهي الصلاحية');
        else if (days <= 30) reasons.push(`الصلاحية قريبة (${days} يوم)`);
      }
    } else {
      reasons.push('EXP غير موجود');
    }
    return reasons;
  }

  function renderWarnings(parsed, status) {
    // NO-BLOCK: show reasons when status is WARN (or when backend attaches warnings/checks)
    const host = $('#statusPill')?.closest('.kv')?.parentElement;
    if (!host) return;

    let box = $('#warnBox');
    if (!box) {
      box = document.createElement('div');
      box.id = 'warnBox';
      box.style.marginTop = '10px';
      box.style.padding = '10px 12px';
      box.style.borderRadius = '12px';
      box.style.border = '1px solid rgba(245,158,11,.35)';
      box.style.background = 'rgba(245,158,11,.08)';
      box.style.display = 'none';
      box.style.maxWidth = '100%';
      box.style.overflow = 'hidden';
      box.innerHTML = '<div style="font-weight:700;margin-bottom:6px">تحذيرات</div><ul id="warnList" style="margin:0;padding:0 18px;line-height:1.7"></ul>';
      host.appendChild(box);
    }

    let list = $('#warnList');
    if (!list) {
      box.innerHTML = '<div style="font-weight:900;margin-bottom:6px;">أسباب التحذير</div><ul id="warnList" style="margin:0;padding:0 18px;"></ul>';
      list = $('#warnList');
    }
    const reasons = [];

    // Prefer backend reasons if present on lastScan
    const last = state.lastScan || {};
    const backendChecks = last?.parsed?.checks || last?.parsed?.warnings || null;

    if (Array.isArray(backendChecks)) {
      for (const c of backendChecks) {
        const msg = c.message || c.msg || c.reason || c.code || '';
        if (msg) reasons.push(msg);
      }
    }

    // Always add computed reasons for operator clarity
    for (const r of computeWarnReasons(parsed || {})) {
      if (!reasons.includes(r)) reasons.push(r);
    }

    if (String(status).toUpperCase() === 'WARN' && reasons.length) {
      box.style.display = 'block';
      list.innerHTML = reasons.map(r => `<li>${escapeHtml(r)}</li>`).join('');
    } else {
      box.style.display = 'none';
      list.innerHTML = '';
    }
  }


  function buildCommitPayload() {
    const tpl = $('#tplSelect')?.value || 'RECEIPT';
    const parsed = state.lastScan?.parsed || {};
    return {
      template: tpl,
      raw: state.lastScan?.raw || '',
      parsed,
      client_ts: new Date().toISOString(),
    };
  }

  async function commit(type) {
    try {
      if (!state.lastScan?.raw) throw new Error('ابدأ المسح أولاً');
      const payload = buildCommitPayload();
      const res = await apiPost('/api/commit', { ...payload, commitType: type });
      $('#commitOut').textContent = JSON.stringify(res, null, 2);
      toast('تم الإرسال', 'ok');
    } catch (e) {
      const msg = e.message || String(e);
      $('#commitOut').textContent = JSON.stringify({ error: msg }, null, 2);

      if (/Failed to fetch|NetworkError|ECONN|timeout/i.test(msg) && state.lastScan?.raw) {
        const job = { type: 'commit', commitType: type, payload: buildCommitPayload(), queuedAt: new Date().toISOString() };
        state.queue.push(job);
        localStorage.setItem('gs1hub.queue', JSON.stringify(state.queue));
        renderQueue();
        toast('تم الحفظ في Offline Queue', 'warn');
        return;
      }
      toast('Commit failed', 'bad');
    }
  }

  // ---- Offline Queue
  function renderQueue() {
    $('#qPending').textContent = String(state.queue.length);
  }

  async function syncQueue() {
    if (!state.queue.length) return toast('لا يوجد Pending', 'warn');
    try {
      const copy = [...state.queue];
      for (const job of copy) await apiPost('/api/queue/consume', job);
      state.queue = [];
      localStorage.setItem('gs1hub.queue', JSON.stringify(state.queue));
      renderQueue();
      toast('Sync OK', 'ok');
    } catch (e) {
      toast('Sync failed: ' + (e.message || e), 'bad');
    }
  }

  // ---- Admin bindings
  function bindAdmin() {
    $('#btnRefreshDash')?.addEventListener('click', () => refreshDashboard().catch(err => toast(err.message || err, 'bad')));
    $('#btnRefreshCases')?.addEventListener('click', () => refreshCases().catch(err => toast(err.message || err, 'bad')));
    $('#btnCreateUser')?.addEventListener('click', () => createUser().catch(err => toast(err.message || err, 'bad')));
    $('#btnAudit')?.addEventListener('click', () => refreshAudit().catch(err => toast(err.message || err, 'bad')));
    $('#caseStatus')?.addEventListener('change', () => refreshCases().catch(() => {}));
    $('#caseDecision')?.addEventListener('change', () => refreshCases().catch(() => {}));
    $('#caseQ')?.addEventListener('input', debounce(() => refreshCases().catch(() => {}), 300));
  }

  async function refreshDashboard() {
    const r = await apiGet('/api/admin/dashboard');
    $('#kpiTotal').textContent = String(r.total ?? '—');
    $('#kpiPass').textContent = String(r.pass ?? '—');
    $('#kpiWarn').textContent = String(r.warn ?? '—');
    $('#kpiBlock').textContent = String(r.block ?? '—');
  }

  async function refreshCases() {
    const qs = new URLSearchParams();
    const st = $('#caseStatus').value; if (st) qs.set('status', st);
    const dc = $('#caseDecision').value; if (dc) qs.set('decision', dc);
    const q = $('#caseQ').value.trim(); if (q) qs.set('q', q);

    const r = await apiGet('/api/cases?' + qs.toString());
    const body = $('#casesBody');
    if (!Array.isArray(r) || !r.length) {
      body.innerHTML = '<div class="muted">لا توجد حالات.</div>';
      return;
    }
    body.innerHTML = r.map(c => `
      <div class="list__item">
        <div class="mono">${escapeHtml(c.id || '')}</div>
        <div class="mono" style="opacity:.85">${escapeHtml((c.raw || '').slice(0, 60))}</div>
        <div class="mono" style="opacity:.75">${escapeHtml((c.checks || '').toString().slice(0, 40))}</div>
        <div><button class="btn btn--ghost" data-case="${escapeHtml(c.id || '')}">Open</button></div>
      </div>
    `).join('');

    $$('[data-case]').forEach(btn => btn.addEventListener('click', () => openCase(btn.getAttribute('data-case'))));
  }

  async function openCase(id) {
    const r = await apiGet('/api/cases/' + encodeURIComponent(id));
    const out = `<pre class="pre">${escapeHtml(JSON.stringify(r, null, 2))}</pre>`;
    if (window.__showModal) window.__showModal(`Case #${escapeHtml(String(id))}`, out);
    else alert(JSON.stringify(r, null, 2));
  }

  async function refreshUsers() {
    const r = await apiGet('/api/users');
    const host = $('#usersList') || $('#usersBody');
    if (!host) return;

    if (!Array.isArray(r) || !r.length) {
      host.innerHTML = '<div class="muted">لا يوجد مستخدمين.</div>';
      return;
    }

    host.innerHTML = r.map(u => `
      <div class="list__row">
        <div style="min-width:0;">
          <div style="font-weight:900;">${escapeHtml(u.username || '')}</div>
          <div class="muted mono" style="font-size:12px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
            ${escapeHtml(u.id || '')}
          </div>
        </div>
        <div class="badge" style="justify-content:center;">${escapeHtml(u.role || '')}</div>
        <button class="btn btn--ghost" data-user-view="${escapeHtml(u.username || '')}">View</button>
      </div>
    `).join('');

    // View details (Pilot)
    $$('#usersList [data-user-view], #usersBody [data-user-view]').forEach(btn => {
      btn.addEventListener('click', () => {
        const uname = btn.getAttribute('data-user-view') || '';
        const user = r.find(x => (x.username || '') === uname) || null;
        const editor = $('#userEditor');
        if (!editor) return;
        editor.innerHTML = user
          ? `<pre class="pre">${escapeHtml(JSON.stringify(user, null, 2))}</pre>`
          : '<div class="muted">User not found.</div>';
      });
    });
  }

  async function createUser() {
    const role = (state.me && state.me.role) || '';
    if (role !== 'admin') {
      toast('هذه العملية متاحة للإدارة فقط', 'warn');
      return;
    }

    const username = ($('#newUser')?.value || '').trim();
    const password = ($('#newPass')?.value || '').trim();
    const r = $('#newRole');
    const newRole = (r && r.value) ? r.value : 'operator';

    if (!username || !password) {
      toast('أدخل اسم المستخدم وكلمة المرور', 'warn');
      return;
    }

    await apiPost('/api/users', { username, password, role: newRole });
    toast('تم إنشاء المستخدم', 'ok');

    try { $('#newUser').value = ''; $('#newPass').value = ''; } catch {}
    await refreshUsers();
  }

  async function refreshAudit() {
    const type = $('#auditType')?.value || '';
    const r = await apiGet('/api/audit' + (type ? `?type=${encodeURIComponent(type)}` : ''));
    $('#auditOut').textContent = JSON.stringify(r, null, 2);
  }

  function bindDocs() { /* static */ }

  // ---- Remote parse/validate probing (optional)
  async function tryRemoteParseValidate(raw) {
    const candidates = [
      { path: '/api/parse-validate', body: { raw } },
      { path: '/api/parse', body: { raw } },
      { path: '/api/validate', body: { raw } },
      { path: '/api/scan/validate', body: { raw } },
    ];
    for (const c of candidates) {
      const out = await tryPostNoThrow(c.path, c.body);
      if (out?.ok) return out.data;
      if (out?.status && out.status !== 404) return null;
    }
    return null;
  }

  async function tryPostNoThrow(path, body) {
    try {
      const res = await fetch(state.apiBase + path, {
        method: 'POST',
        headers: { ...authHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify(body || {}),
      });
      const txt = await res.text();
      let data; try { data = txt ? JSON.parse(txt) : null; } catch { data = txt; }
      return { ok: res.ok, status: res.status, data };
    } catch {
      return { ok: false, status: 0, data: null };
    }
  }

  // ---- Local GS1 AI parse (best-effort)
  function parseGS1(raw) {
    const s = String(raw || '').trim();
    if (!s) return {};

    if (/\(\d{2,4}\)/.test(s)) {
      const ai = {};
      const re = /\((\d{2,4})\)/g;
      const parts = [];
      let m, lastIdx = 0, lastAI = null;

      while ((m = re.exec(s))) {
        const aiCode = m[1];
        if (lastAI !== null) parts.push([lastAI, s.slice(lastIdx, m.index)]);
        lastAI = aiCode;
        lastIdx = re.lastIndex;
      }
      if (lastAI !== null) parts.push([lastAI, s.slice(lastIdx)]);

      for (const [k, v] of parts) ai[k] = (v || '').trim();
      return normalizeAI(ai, s);
    }

    const GS = String.fromCharCode(29);
    const ai = {};
    let i = 0;

    const fixed = { '01': 14, '02': 14, '11': 6, '13': 6, '15': 6, '17': 6, '20': 2 };
    const variableMax = { '10': 20, '21': 20, '30': 8, '37': 8, '240': 30, '241': 30, '242': 6, '243': 20 };

    while (i < s.length) {
      const try4 = s.slice(i, i + 4);
      const try3 = s.slice(i, i + 3);
      const try2 = s.slice(i, i + 2);

      const code =
        (try4 in variableMax || try4 in fixed) ? try4 :
        (try3 in variableMax || try3 in fixed) ? try3 :
        try2;

      const isFixed = Object.prototype.hasOwnProperty.call(fixed, code);
      const isVar = Object.prototype.hasOwnProperty.call(variableMax, code);
      if (!isFixed && !isVar) break;

      i += code.length;

      if (isFixed) {
        ai[code] = s.slice(i, i + fixed[code]);
        i += fixed[code];
      } else {
        const max = variableMax[code];
        let end = s.indexOf(GS, i);
        if (end === -1) end = Math.min(i + max, s.length);
        ai[code] = s.slice(i, Math.min(end, i + max));
        i = end + 1;
      }
    }
    return normalizeAI(ai, s);
  }

  function normalizeAI(ai, raw) {
    const out = { ai, raw };
    if (ai['01']) out.gtin = ai['01'];
    if (ai['17']) out.expiry = ai['17'];
    if (ai['10']) out.lot = ai['10'];
    if (ai['21']) out.serial = ai['21'];
    if (ai['30'] || ai['37']) out.qty = ai['30'] || ai['37'];

    if (out.expiry && /^\d{6}$/.test(out.expiry)) {
      const yy = out.expiry.slice(0, 2);
      const mm = out.expiry.slice(2, 4);
      const dd = out.expiry.slice(4, 6);
      out.expiry_iso = `20${yy}-${mm}-${dd}`;
    }
    return out;
  }

  function localDecision(parsed) {
    const gtin = parsed.gtin || '';
    if (!gtin || gtin.length < 14) return 'WARN'; // NO-BLOCK mode

    const exp = parsed.expiry_iso || '';
    if (exp) {
      const d = new Date(exp + 'T00:00:00Z');
      if (!isNaN(d.valueOf())) {
        const days = Math.floor((d - new Date()) / (1000 * 60 * 60 * 24));
        if (days < 0) return 'WARN'; // NO-BLOCK mode
        if (days <= 30) return 'WARN';
      }
    }
    return 'PASS';
  }

  // ---- API helpers
  function resolveApiBase() {
    const qp = new URLSearchParams(location.search);
    const qApi = qp.get('api');
    const wApi = (window.__API_BASE__ || '').trim();
    if (qApi) return qApi.replace(/\/$/, '');
    if (wApi) return wApi.replace(/\/$/, '');
    return '';
  }

  async function apiGet(path) {
    const res = await fetch(state.apiBase + path, { headers: authHeaders() });
    return await handle(res);
  }
  async function apiPost(path, body) {
    const res = await fetch(state.apiBase + path, {
      method: 'POST',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    return await handle(res);
  }
  function authHeaders() {
    return state.token ? { Authorization: 'Bearer ' + state.token } : {};
  }
  async function handle(res) {
    const txt = await res.text();
    let data; try { data = txt ? JSON.parse(txt) : null; } catch { data = txt; }
    if (!res.ok) {
      const msg = data?.error ? data.error : `HTTP ${res.status}`;
      const err = new Error(msg);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  // ---- Utils
  function safeJson(s) { try { return JSON.parse(s); } catch { return null; } }
  function escapeHtml(s) {
    return String(s || '').replace(/[&<>"']/g, (c) => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
  }
  function debounce(fn, ms) { let t; return (...args)=>{ clearTimeout(t); t=setTimeout(()=>fn(...args), ms); }; }

  function toast(msg, kind) {
    const el = $('#toast');
    if (!el) return console.log('[toast]', kind || 'info', msg);
    el.hidden = false;
    el.className = 'toast' + (kind ? ` toast--${kind}` : '');
    el.innerHTML = `<span class="toast__dot"></span><div class="toast__msg">${escapeHtml(msg)}</div>`;
    clearTimeout(toast._t);
    toast._t = setTimeout(() => (el.hidden = true), 2800);
  }

  function setAlert(sel, msg, kind) {
    const el = $(sel);
    if (!el) return;
    if (!msg) {
      el.hidden = true;
      el.textContent = '';
      return;
    }
    el.hidden = false;
    el.textContent = msg;
    el.style.borderColor =
      kind === 'bad' ? 'rgba(255,77,109,.25)' :
      kind === 'ok'  ? 'rgba(34,197,94,.25)' :
                       'rgba(255,255,255,.10)';
    el.style.background =
      kind === 'bad' ? 'rgba(255,77,109,.08)' :
      kind === 'ok'  ? 'rgba(34,197,94,.08)' :
                       'rgba(255,255,255,.04)';
  }

  async function registerSW() {
    if (!('serviceWorker' in navigator)) return;
    try { await navigator.serviceWorker.register('./sw.js'); } catch {}
  }

  boot().catch((e)=>{ console.error(e); });
})();
