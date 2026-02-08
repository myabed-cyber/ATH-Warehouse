/* ATH / GS1 UDI Hub — Premium SFX (WebAudio, user-gesture safe)
   - Uses WebAudio (no external libs)
   - Autoplay-safe: arms on first user interaction
   - Optional toggle + volume persisted in localStorage
*/
(function () {
  const STORE_KEY = 'gs1hub.sfx';
  const DEFAULTS = { enabled: true, volume: 0.55 };
  let cfg = { ...DEFAULTS };
  try {
    const saved = JSON.parse(localStorage.getItem(STORE_KEY) || 'null');
    if (saved && typeof saved === 'object') cfg = { ...cfg, ...saved };
  } catch {}

  let ctx = null;
  let master = null;

  const last = { hover: 0, click: 0, scan: 0, status: 0 };
  const now = () => (typeof performance !== 'undefined' ? performance.now() : Date.now());

  function saveCfg() {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(cfg)); } catch {}
  }

  function ensure() {
    if (!cfg.enabled) return null;
    if (!ctx) {
      const AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return null;
      ctx = new AC();
      master = ctx.createGain();
      master.gain.value = clamp(cfg.volume, 0, 1);
      master.connect(ctx.destination);
    }
    if (ctx.state === 'suspended') {
      ctx.resume().catch(() => {});
    }
    return ctx;
  }

  function clamp(n, a, b) { return Math.max(a, Math.min(b, n)); }

  function playTone({ type='sine', f=440, f2=null, dur=0.08, gain=0.05, glide=null, lp=1400 }) {
    const c = ensure();
    if (!c) return;

    const t = c.currentTime;
    const osc1 = c.createOscillator();
    const g = c.createGain();
    const filter = c.createBiquadFilter();
    filter.type = 'lowpass';
    filter.frequency.value = lp;

    osc1.type = type;
    osc1.frequency.setValueAtTime(f, t);

    if (glide && typeof glide.to === 'number') {
      osc1.frequency.linearRampToValueAtTime(glide.to, t + (glide.time || dur));
    }

    g.gain.setValueAtTime(gain, t);
    g.gain.exponentialRampToValueAtTime(0.001, t + dur);

    osc1.connect(filter);
    filter.connect(g);
    g.connect(master);

    let osc2 = null;
    if (typeof f2 === 'number') {
      osc2 = c.createOscillator();
      osc2.type = type;
      osc2.frequency.setValueAtTime(f2, t);
      osc2.connect(filter);
    }

    osc1.start(t);
    if (osc2) osc2.start(t);
    osc1.stop(t + dur);
    if (osc2) osc2.stop(t + dur);
  }

  function throttle(key, ms) {
    const t = now();
    if (t - (last[key] || 0) < ms) return false;
    last[key] = t;
    return true;
  }

  // Public API
  const SFX = {
    arm() { ensure(); }, // user gesture should call this once
    setEnabled(v) { cfg.enabled = !!v; saveCfg(); },
    setVolume(v) {
      cfg.volume = clamp(Number(v), 0, 1);
      saveCfg();
      if (master) master.gain.value = cfg.volume;
    },
    get config() { return { ...cfg }; },

    hover() {
      if (!throttle('hover', 80)) return;
      playTone({ type: 'sine', f: 620, dur: 0.045, gain: 0.018, lp: 1700 });
    },
    click() {
      if (!throttle('click', 60)) return;
      playTone({ type: 'triangle', f: 130, dur: 0.09, gain: 0.045, lp: 1200 });
    },
    success() {
      if (!throttle('status', 120)) return;
      // pleasant chord
      playTone({ type: 'sine', f: 523.25, f2: 659.25, dur: 0.45, gain: 0.05, lp: 2200 });
    },
    warn() {
      if (!throttle('status', 120)) return;
      playTone({ type: 'square', f: 740, dur: 0.10, gain: 0.03, lp: 900 });
    },
    error() {
      if (!throttle('status', 140)) return;
      playTone({ type: 'sawtooth', f: 90, dur: 0.20, gain: 0.06, lp: 650 });
    },
    scanStart() {
      if (!throttle('scan', 180)) return;
      playTone({ type: 'sine', f: 210, dur: 0.28, gain: 0.05, glide: { to: 820, time: 0.28 }, lp: 1800 });
    },
  };

  // Expose
  window.SFX = SFX;

  // Arm on first user interaction (autoplay-safe)
  const armOnce = () => { try { SFX.arm(); } catch {} };
  document.addEventListener('pointerdown', armOnce, { once: true, passive: true });
  document.addEventListener('keydown', armOnce, { once: true });

  // Global UX hooks (subtle)
  document.addEventListener('pointerover', (e) => {
    const t = e.target;
    if (!t) return;
    if (t.closest && t.closest('button, a, .nav-item, .menu-item, .action-btn, .btn')) SFX.hover();
  }, { passive: true });

  document.addEventListener('click', (e) => {
    const t = e.target;
    if (!t) return;
    if (t.closest && t.closest('button, a, .nav-item, .menu-item, .action-btn, .btn')) SFX.click();
  }, { passive: true });

  // Premium toggle UI (non-invasive)
  function injectToggle() {
    // try to place near header controls if available
    const anchor = document.querySelector('#headerControls, .header-controls, .topbar-controls, header .controls, header .right, .topbar .right') || null;

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'sfx-toggle';
    btn.setAttribute('aria-label', 'Toggle sound');
    btn.title = 'Sound';
    btn.innerHTML = '<span class="sfx-ic">🔊</span><span class="sfx-txt">Sound</span>';

    btn.addEventListener('click', () => {
      SFX.setEnabled(!cfg.enabled);
      btn.classList.toggle('muted', !cfg.enabled);
      btn.querySelector('.sfx-ic').textContent = cfg.enabled ? '🔊' : '🔇';
      // play feedback only when enabling (avoids silence confusion)
      if (cfg.enabled) { SFX.arm(); SFX.click(); }
    });

    // style injection
    const st = document.createElement('style');
    st.textContent = `
      .sfx-toggle{
        display:inline-flex; align-items:center; gap:8px;
        padding:8px 12px; border-radius:999px;
        border:1px solid rgba(0,0,0,.08);
        background: rgba(255,255,255,.72);
        color:#0f172a; font-weight:800; font-size:12px;
        cursor:pointer; user-select:none;
        backdrop-filter: blur(10px);
        box-shadow: 0 10px 20px rgba(2,6,23,.08);
        transition: transform .15s ease, background .15s ease, border-color .15s ease, opacity .15s ease;
      }
      html[data-theme="dark"] .sfx-toggle{
        background: rgba(15,23,42,.55);
        border-color: rgba(255,255,255,.10);
        color: #f8fafc;
        box-shadow: 0 18px 30px rgba(0,0,0,.25);
      }
      .sfx-toggle:hover{ transform: translateY(-1px); border-color: rgba(59,130,246,.35); }
      .sfx-toggle.muted{ opacity:.7; }
      .sfx-toggle .sfx-txt{ font-weight:900; letter-spacing:.02em; }
      /* fallback positioning if no anchor */
      .sfx-toggle.sfx-float{
        position: fixed; right: 14px; bottom: 14px; z-index: 9999;
      }
    `;
    document.head.appendChild(st);

    if (anchor) {
      anchor.appendChild(btn);
    } else {
      btn.classList.add('sfx-float');
      document.body.appendChild(btn);
    }

    btn.classList.toggle('muted', !cfg.enabled);
    btn.querySelector('.sfx-ic').textContent = cfg.enabled ? '🔊' : '🔇';
  }

  document.addEventListener('DOMContentLoaded', injectToggle);
})();
