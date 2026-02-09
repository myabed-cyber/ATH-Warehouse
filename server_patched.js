import express from "express";
import cors from "cors";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";
import { fileURLToPath } from "url";

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------- Config ----------------
const PORT = Number(process.env.PORT || 8080);
let JWT_SECRET_EFFECTIVE = process.env.JWT_SECRET_EFFECTIVE || "";
const NODE_ENV = (process.env.NODE_ENV || "development").toLowerCase();
const IS_PROD = NODE_ENV === "production";
if (IS_PROD && (!JWT_SECRET_EFFECTIVE || JWT_SECRET_EFFECTIVE.length < 24)) {
  throw new Error("JWT_SECRET_EFFECTIVE must be set (>=24 chars) in production.");
}
if (!IS_PROD && !JWT_SECRET_EFFECTIVE) {
  console.warn("[WARN] JWT_SECRET_EFFECTIVE not set. Using a weak dev default.");
  JWT_SECRET_EFFECTIVE = "dev_secret_change_me";
}

const NO_BLOCK = String(process.env.NO_BLOCK ?? "true").toLowerCase() !== "false";

// Supabase Postgres connection string (Project Settings → Database → Connection string)
const DATABASE_URL = process.env.DATABASE_URL || process.env.SUPABASE_DATABASE_URL;
if (!DATABASE_URL) {
  console.warn("[WARN] DATABASE_URL not set. Set it to your Supabase Postgres connection string.");
}

// Seed accounts (provided via env; no insecure hard-coded defaults)
const SEED_ADMIN_USER = (process.env.SEED_ADMIN_USER || "").trim();
const SEED_ADMIN_PASS = (process.env.SEED_ADMIN_PASS || "").trim();
const SEED_OPERATOR_USER = (process.env.SEED_OPERATOR_USER || "").trim();
const SEED_OPERATOR_PASS = (process.env.SEED_OPERATOR_PASS || "").trim();

// Seeding mode: off | once | upsert
// - off   : do nothing
// - once  : seed only when users table is empty (default when seed vars are provided)
// - upsert: upsert the seed usernames (safe reset for those usernames only)
const SEED_MODE = (process.env.SEED_MODE || ((SEED_ADMIN_USER || SEED_OPERATOR_USER) ? "once" : "off")).toLowerCase();

// Optional: prevent app from starting without an admin when users table is empty
const SEED_STRICT_BOOTSTRAP = (process.env.SEED_STRICT_BOOTSTRAP || "true").toLowerCase() === "true";

// CORS: if empty => allow all (recommended for same-origin deployment)
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// BC Integration placeholders (not used unless BC_MODE=LIVE)
const BC_MODE = (process.env.BC_MODE || "SIMULATED").toUpperCase(); // SIMULATED | LIVE
const BC_BASE_URL = process.env.BC_BASE_URL || ""; // e.g. https://api.businesscentral.dynamics.com/v2.0/<tenant>/<env>/api/...
const BC_COMPANY_ID = process.env.BC_COMPANY_ID || ""; // company id if needed

// ---------------- Helpers ----------------
function nowIso() { return new Date().toISOString(); }
function uuid() { return crypto.randomUUID(); }

function stableStringify(value) {
  const seen = new WeakSet();
  const helper = (v) => {
    if (v === null || typeof v !== "object") return v;
    if (seen.has(v)) return "[Circular]";
    seen.add(v);
    if (Array.isArray(v)) return v.map(helper);
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = helper(v[k]);
    return out;
  };
  return JSON.stringify(helper(value));
}
function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}
function hashPayload(obj) {
  return sha256Hex(stableStringify(obj));
}

// ---------------- Postgres (Supabase) ----------------
let _pool = null;

function getPool() {
  if (_pool) return _pool;
  if (!DATABASE_URL) {
    throw new Error("DATABASE_URL is not set. Database features require Supabase Postgres.");
  }
  _pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: process.env.PGSSL === "false" ? false : { rejectUnauthorized: false },
  });
  return _pool;
}

async function q(text, params = []) {
  const pool = getPool();
  const client = await pool.connect();
  try {
    return await client.query(text, params);
  } finally {
    client.release();
  }
}


async function ensureSchema() {
  // Base schema (create-if-not-exists)
  await q(`
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";

    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY,
      username text UNIQUE NOT NULL,
      password_hash text NOT NULL,
      role text NOT NULL CHECK(role IN ('operator','admin','auditor')),
      is_active boolean NOT NULL DEFAULT true,
      created_at timestamptz NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS policies (
      id uuid PRIMARY KEY,
      name text NOT NULL,
      version int NOT NULL,
      is_active boolean NOT NULL,
      config jsonb NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS scans (
      id text PRIMARY KEY,
      created_at timestamptz NOT NULL DEFAULT now(),
      scan_id text NOT NULL,
      raw_string text NOT NULL,
      normalized text NOT NULL,
      decision text NOT NULL CHECK(decision IN ('PASS','WARN','BLOCK')),
      checks jsonb NOT NULL,
      parsed jsonb NOT NULL,
      context jsonb NOT NULL
    );

    CREATE TABLE IF NOT EXISTS cases (
      id text PRIMARY KEY,
      created_at timestamptz NOT NULL DEFAULT now(),
      status text NOT NULL CHECK(status IN ('NEW','IN_PROGRESS','RESOLVED')),
      decision text NOT NULL CHECK(decision IN ('WARN','BLOCK')),
      scan_id text NOT NULL,
      user_id text NOT NULL,
      raw_string text NOT NULL,
      checks jsonb NOT NULL,
      context jsonb NOT NULL,
      comment text,
      resolution text
    );

    CREATE TABLE IF NOT EXISTS idempotency (
      key text PRIMARY KEY,
      created_at timestamptz NOT NULL DEFAULT now(),
      request_hash text,
      response jsonb NOT NULL
    );

    CREATE TABLE IF NOT EXISTS gtin_map (
      gtin text PRIMARY KEY,
      item_no text NOT NULL,
      uom text,
      status text NOT NULL DEFAULT 'ACTIVE',
      updated_at timestamptz NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS audit_events (
      id uuid PRIMARY KEY,
      created_at timestamptz NOT NULL DEFAULT now(),
      actor_username text,
      actor_role text,
      event_type text NOT NULL,
      entity_type text,
      entity_id text,
      payload jsonb NOT NULL
    );

    CREATE TABLE IF NOT EXISTS bc_postings (
      id uuid PRIMARY KEY,
      created_at timestamptz NOT NULL DEFAULT now(),
      scan_id text NOT NULL,
      posting_intent text NOT NULL,
      idempotency_key text NOT NULL,
      request_hash text NOT NULL,
      status text NOT NULL,
      response jsonb NOT NULL,
      actor_username text
    );

    CREATE UNIQUE INDEX IF NOT EXISTS uq_bc_postings_scan_intent ON bc_postings(scan_id, posting_intent);

    CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
    CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events(created_at);
    CREATE INDEX IF NOT EXISTS idx_bc_postings_created_at ON bc_postings(created_at);
  

-- -------- Additional tables for concurrent warehouse work (sessions/transactions) --------
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS public.items_cache (
  item_no text PRIMARY KEY,
  item_name text NOT NULL,
  is_top200 boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.work_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_type text NOT NULL CHECK(session_type IN ('RECEIVING','PICKING','CYCLE_COUNT','TRANSFER','OTHER')),
  reference_no text,
  created_by text NOT NULL,
  status text NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN','CLOSED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  closed_at timestamptz
);

CREATE TABLE IF NOT EXISTS public.work_lines (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id uuid NOT NULL REFERENCES public.work_sessions(id) ON DELETE CASCADE,
  item_no text NOT NULL,
  expected_qty numeric NOT NULL CHECK(expected_qty >= 0),
  scanned_qty numeric NOT NULL DEFAULT 0 CHECK(scanned_qty >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(session_id, item_no)
);

CREATE TABLE IF NOT EXISTS public.tx_log (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by text NOT NULL,
  tx_type text NOT NULL,
  gtin text NOT NULL,
  item_no text NOT NULL,
  qty numeric NOT NULL CHECK(qty > 0),
  lot text,
  exp text,
  raw_scan text,
  session_id uuid REFERENCES public.work_sessions(id) ON DELETE SET NULL,
  status text NOT NULL DEFAULT 'COMPLETE',
  expected_qty numeric
);

CREATE INDEX IF NOT EXISTS idx_items_cache_top200 ON public.items_cache(is_top200);
CREATE INDEX IF NOT EXISTS idx_work_sessions_status ON public.work_sessions(status);
CREATE INDEX IF NOT EXISTS idx_work_lines_session ON public.work_lines(session_id);
CREATE INDEX IF NOT EXISTS idx_tx_log_created_at ON public.tx_log(created_at);

-- -------- RPC helpers used by operator endpoints --------
CREATE OR REPLACE FUNCTION public.rpc_qty_suggestion(p_session_id uuid, p_item_no text)
RETURNS TABLE(found boolean, expected_qty numeric, scanned_qty numeric, remaining_qty numeric)
LANGUAGE sql
STABLE
AS $$
  SELECT
    true AS found,
    wl.expected_qty,
    wl.scanned_qty,
    GREATEST(wl.expected_qty - wl.scanned_qty, 0) AS remaining_qty
  FROM public.work_lines wl
  WHERE wl.session_id = p_session_id AND wl.item_no = p_item_no
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION public.rpc_map_gtin_operator(p_gtin text, p_item_no text, p_actor text)
RETURNS TABLE(ok boolean, action text, gtin text, item_no text)
LANGUAGE plpgsql
AS $$
BEGIN
  IF p_gtin IS NULL OR length(trim(p_gtin)) = 0 OR p_item_no IS NULL OR length(trim(p_item_no)) = 0 THEN
    RETURN QUERY SELECT false, 'INVALID_INPUT', p_gtin, p_item_no;
    RETURN;
  END IF;

  INSERT INTO public.gtin_map (gtin, item_no, uom, status, updated_at)
  VALUES (trim(p_gtin), trim(p_item_no), NULL, 'ACTIVE', now())
  ON CONFLICT (gtin) DO UPDATE SET
    item_no = EXCLUDED.item_no,
    status = EXCLUDED.status,
    updated_at = now();

  RETURN QUERY SELECT true, 'UPSERT', trim(p_gtin), trim(p_item_no);
END;
$$;

`);

  // Evolutions for older deployments
  await q(`ALTER TABLE idempotency ADD COLUMN IF NOT EXISTS request_hash text;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active boolean NOT NULL DEFAULT true;`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();`);
  await q(`ALTER TABLE gtin_map ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();`);
}

async function seed() {
  const mode = String(process.env.SEED_MODE || "once").toLowerCase(); // once | upsert | reset | off
  if (mode === "off") {
    console.log("[SEED] SEED_MODE=off -> skip");
    return;
  }

  const strict = String(process.env.SEED_STRICT_BOOTSTRAP || "").toLowerCase() === "true";
  const force = String(process.env.SEED_FORCE || "").toLowerCase() === "true";
  const seedVersion = String(process.env.SEED_VERSION || "1");

  const adminUser = process.env.SEED_ADMIN_USER || "admin";
  const adminPass = process.env.SEED_ADMIN_PASS;
  const operatorUser = process.env.SEED_OPERATOR_USER || "testuser";
  const operatorPass = process.env.SEED_OPERATOR_PASS;

  if (!adminPass || !operatorPass) {
    const msg =
      "[SEED] Missing SEED_ADMIN_PASS or SEED_OPERATOR_PASS. " +
      "Set them in Northflank Secrets. " +
      (strict ? "SEED_STRICT_BOOTSTRAP=true -> refusing to start." : "Skipping seed for now.");
    if (strict) throw new Error(msg);
    console.warn(msg);
    return;
  }

  // Ensure seed metadata table exists (so we can make seeding idempotent and controllable).
  await q(`
    CREATE TABLE IF NOT EXISTS seed_meta (
      id INT PRIMARY KEY DEFAULT 1,
      seed_version TEXT NOT NULL,
      seed_hash TEXT NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  // Hash includes the seed inputs, so changing SEED_* values can trigger a re-seed in upsert/reset modes.
  const seedHash = crypto
    .createHash("sha256")
    .update(
      JSON.stringify({
        adminUser,
        adminPass,
        operatorUser,
        operatorPass,
        seedVersion,
      })
    )
    .digest("hex");

  const metaRes = await q("SELECT seed_version, seed_hash, applied_at FROM seed_meta WHERE id=1");
  const meta = metaRes.rows[0];

  // Decide whether to run seed:
  // - first time (no meta row): run
  // - SEED_FORCE=true: run
  // - version changed: run (any mode except off)
  // - hash changed: run only for upsert/reset
  let shouldRun = force || !meta;

  if (!shouldRun && meta) {
    if (meta.seed_version !== seedVersion) shouldRun = true;
    else if (meta.seed_hash !== seedHash && (mode === "upsert" || mode === "reset")) shouldRun = true;
  }

  // In "once" mode, never re-run once meta exists (even if values change).
  if (mode === "once" && meta && !force) {
    shouldRun = false;
  }

  if (!shouldRun) {
    console.log(`[SEED] Up-to-date (mode=${mode}, version=${meta?.seed_version}) -> skip`);
    return;
  }

  console.log(`[SEED] Running seed (mode=${mode}, version=${seedVersion}, force=${force})...`);

  const adminHash = bcrypt.hashSync(String(adminPass), 10);
  const operatorHash = bcrypt.hashSync(String(operatorPass), 10);


  if (mode === "reset") {
    // WARNING: destructive. Use only in dev / controlled environments.
    await q("DELETE FROM users");
  }

  // Upsert users (safe + repeatable).
  await q(
    `
    INSERT INTO users (id, username, password_hash, role, is_active)
    VALUES (gen_random_uuid(), $1, $2, $3, true)
    ON CONFLICT (username) DO UPDATE
      SET password_hash = EXCLUDED.password_hash,
          role = EXCLUDED.role,
          is_active = true
    `,
    [adminUser, adminHash, "admin"]
  );

  await q(
    `
    INSERT INTO users (id, username, password_hash, role, is_active)
    VALUES (gen_random_uuid(), $1, $2, $3, true)
    ON CONFLICT (username) DO UPDATE
      SET password_hash = EXCLUDED.password_hash,
          role = EXCLUDED.role,
          is_active = true
    `,
    [operatorUser, operatorHash, "operator"]
  );

  // Record seed application.
  await q(
    `
    INSERT INTO seed_meta (id, seed_version, seed_hash, applied_at)
    VALUES (1, $1, $2, NOW())
    ON CONFLICT (id) DO UPDATE
      SET seed_version = EXCLUDED.seed_version,
          seed_hash = EXCLUDED.seed_hash,
          applied_at = NOW()
    `,
    [seedVersion, seedHash]
  );

  console.log("[SEED] Done.");
}
// ---------------- Auth ----------------
function signToken(user) {
  return jwt.sign({ sub: user.id, username: user.username, role: user.role }, JWT_SECRET_EFFECTIVE, { expiresIn: "8h" });
}

function auth(req, res, next) {
  const h = req.header("Authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: "Unauthorized" });
  try {
    const payload = jwt.verify(m[1], JWT_SECRET_EFFECTIVE);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

function requireRole(...roles) {
  return async (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Unauthorized" });
    if (!roles.includes(req.user.role)) {
      // Audit unauthorized access attempt
      await audit({
        actor: req.user,
        event_type: "ACCESS_DENIED",
        entity_type: "endpoint",
        entity_id: req.path,
        payload: { required_roles: roles, user_role: req.user.role, ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress }
      });
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  };
}

// ---------------- Audit ----------------
async function audit({ actor, event_type, entity_type = null, entity_id = null, payload = {} }) {
  try {
    await q(
      `INSERT INTO audit_events (id, actor_username, actor_role, event_type, entity_type, entity_id, payload)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [
        uuid(),
        actor?.username || null,
        actor?.role || null,
        event_type,
        entity_type,
        entity_id,
        payload,
      ]
    );
  } catch (e) {
    // Audit must not break the request path
    console.warn("[WARN] audit insert failed:", e?.message || e);
  }
}

// ---------------- GS1/UDI Parse/Validate ----------------
export const GS = String.fromCharCode(29);

export function normalizeInput(raw) {
  if (!raw) return "";
  let s = String(raw).trim();

  // Strip common symbology identifiers (e.g., ]C1 for GS1-128, ]d2 for GS1 DataMatrix)
  s = s.replace(/^\](C1|c1|d2|D2|Q3|q3|e0|E0)\s*/g, "");

  // Remove whitespace/newlines (scanners sometimes inject them)
  s = s.replace(/\s+/g, "");

  // allow (01)(17) styles
  s = s.replace(/\)\s*\(/g, "").replace(/[()]/g, "");

  // convert literal "\u001d" into GS (ASCII 29)
  s = s.replace(/\\u001[dD]/g, GS);

  return s;
}

function gtinTo14(d) {
  const s = String(d);
  if (s.length === 14) return s;
  if (s.length < 14) return s.padStart(14, "0");
  return s.slice(-14);
}

// GTIN-14 check digit validation (GS1)
function isValidGtin14(gtin14) {
  const s = String(gtin14 || "").replace(/\D/g, "");
  if (s.length !== 14) return false;
  const digits = s.split("").map((x) => Number(x));
  const check = digits[13];
  let sum = 0;
  // weights from right (excluding check digit): 3,1,3,1...
  let weight = 3;
  for (let i = 12; i >= 0; i--) {
    sum += digits[i] * weight;
    weight = weight === 3 ? 1 : 3;
  }
  const calc = (10 - (sum % 10)) % 10;
  return calc === check;
}

function parseExpiryYYMMDD(v) {
  // Returns { iso, y, m, d, expired, near } or { error }
  const s = String(v || "");
  if (!/^\d{6}$/.test(s)) return { error: "EXPIRY_FORMAT_INVALID" };
  const yy = Number(s.slice(0, 2));
  const mm = Number(s.slice(2, 4));
  const dd = Number(s.slice(4, 6));
  if (mm < 1 || mm > 12) return { error: "EXPIRY_MONTH_INVALID" };
  const fullYear = 2000 + yy;
  // DD=00 means end of month
  let day = dd;
  const lastDay = new Date(Date.UTC(fullYear, mm, 0)).getUTCDate(); // mm is 1-based; month=mm gives last day of previous -> use mm
  if (dd === 0) day = lastDay;
  if (day < 1 || day > lastDay) return { error: "EXPIRY_DAY_INVALID" };
  const dt = new Date(Date.UTC(fullYear, mm - 1, day));
  const iso = dt.toISOString().slice(0, 10);
  return { iso, y: fullYear, m: mm, d: day };
}

export // ---------------- Multi-Barcode Parse (GS1 + GTIN/EAN/UPC + SSCC + QR payloads) ----------------

function mod10CheckDigit(num) {
  // Returns the expected Mod10 check digit for the provided numeric string WITHOUT the check digit.
  // Used for GTIN/SSCC check digit validation.
  const s = String(num || "").replace(/\D/g, "");
  let sum = 0;
  // GS1 Mod10: starting from the rightmost digit, weight 3,1,3,1...
  let w = 3;
  for (let i = s.length - 1; i >= 0; i--) {
    sum += (s.charCodeAt(i) - 48) * w;
    w = (w === 3) ? 1 : 3;
  }
  return String((10 - (sum % 10)) % 10);
}

function isValidMod10(value) {
  const v = String(value || "");
  if (!/^\d+$/.test(v) || v.length < 2) return false;
  const body = v.slice(0, -1);
  const cd = v.slice(-1);
  return mod10CheckDigit(body) === cd;
}

function guessNumericKind(norm) {
  if (!/^\d+$/.test(norm)) return null;
  const n = norm.length;
  if (n === 8) return "EAN8";
  if (n === 12) return "UPCA";
  if (n === 13) return "EAN13";
  if (n === 14) return "GTIN14";
  if (n === 18) return "SSCC18";
  return null;
}

// A practical GS1 AI set for "most common" healthcare + warehouse workflows.
// This is NOT the full GS1 spec, but covers the famous / frequent AIs.
const GS1_AI = {
  // fixed length
  "00": { fixed: true, len: 18, name: "SSCC" },
  "01": { fixed: true, len: 14, name: "GTIN" },
  "02": { fixed: true, len: 14, name: "CONTENT_GTIN" },
  "11": { fixed: true, len: 6, name: "PROD_DATE" },
  "12": { fixed: true, len: 6, name: "DUE_DATE" },
  "13": { fixed: true, len: 6, name: "PACK_DATE" },
  "15": { fixed: true, len: 6, name: "BEST_BEFORE" },
  "17": { fixed: true, len: 6, name: "EXPIRY" },
  "20": { fixed: true, len: 2, name: "VARIANT" },
  "402": { fixed: true, len: 17, name: "GIN" },
  "410": { fixed: true, len: 13, name: "SHIP_TO_GLN" },
  "411": { fixed: true, len: 13, name: "BILL_TO" },
  "412": { fixed: true, len: 13, name: "PURCHASE_FROM" },
  "413": { fixed: true, len: 13, name: "SHIP_FOR" },
  "414": { fixed: true, len: 13, name: "LOC_NO" },
  "415": { fixed: true, len: 13, name: "PAY_TO" },
  "416": { fixed: true, len: 13, name: "PROD_SERV_LOC" },
  "7003": { fixed: true, len: 10, name: "EXP_TIME" },
  "8018": { fixed: true, len: 18, name: "GSRN" },

  // variable length (up to max), terminated by GS (ASCII 29) when concatenated
  "10": { fixed: false, max: 20, name: "BATCH_LOT" },
  "21": { fixed: false, max: 20, name: "SERIAL" },
  "22": { fixed: false, max: 29, name: "CPV" },
  "30": { fixed: false, max: 8, name: "VAR_COUNT" },
  "37": { fixed: false, max: 8, name: "COUNT" },
  "240": { fixed: false, max: 30, name: "ADDITIONAL_ID" },
  "241": { fixed: false, max: 30, name: "CUST_PART" },
  "242": { fixed: false, max: 6, name: "MTO_VARIANT" },
  "243": { fixed: false, max: 20, name: "PCN" },
  "250": { fixed: false, max: 30, name: "SECONDARY_SERIAL" },
  "251": { fixed: false, max: 30, name: "REF_TO_SOURCE" },
  "400": { fixed: false, max: 30, name: "ORDER_NO" },
  "401": { fixed: false, max: 30, name: "GINC" },
  "8005": { fixed: false, max: 6, name: "PRICE_PER_UNIT" },
  "8200": { fixed: false, max: 70, name: "PRODUCT_URL" },
};

const GS1_AI_KEYS = Object.keys(GS1_AI).sort((a, b) => b.length - a.length); // match 4-digit before 3/2

function tryMatchAI(norm, i) {
  for (const k of GS1_AI_KEYS) {
    if (norm.startsWith(k, i)) return k;
  }
  return null;
}

export function parseGs1(norm, missingGsBehavior = "BLOCK") {
  const segments = [];
  const meta = {
    kind: "GS1",
    used_lookahead: false,
    missing_gs_detected: false,
    missing_gs_fields: [],
    ai_coverage: "COMMON_SET",
  };

  let i = 0;

  while (i < norm.length) {
    const ai = tryMatchAI(norm, i);
    if (!ai) {
      // Not a known AI at this position → stop (unknown tail)
      segments.push({ ai: "??", value: norm.slice(i) });
      break;
    }

    const spec = GS1_AI[ai];
    i += ai.length;

    // Fixed
    if (spec.fixed) {
      const v = norm.slice(i, i + spec.len);
      if (v.length < spec.len) {
        segments.push({ ai, value: v, meta: { truncated: true } });
        break;
      }
      segments.push({ ai, value: v });
      i += spec.len;
      continue;
    }

    // Variable: consume until GS or next AI boundary (missing GS inference) or max
    let j = i;
    let boundaryByAI = null;

    while (j < norm.length) {
      if (norm[j] === GS) break;

      const nextAI = tryMatchAI(norm, j);
      if (nextAI && j > i) {
        boundaryByAI = j;
        break;
      }

      // enforce max length softly (spec.max)
      if (spec.max && (j - i) >= spec.max) break;
      j++;
    }

    if (boundaryByAI !== null) {
      meta.missing_gs_detected = true;
      meta.missing_gs_fields.push(ai);
      if (String(missingGsBehavior || "BLOCK").toUpperCase() === "LOOKAHEAD") meta.used_lookahead = true;

      segments.push({ ai, value: norm.slice(i, boundaryByAI), meta: { missing_gs: true } });
      i = boundaryByAI;
      continue;
    }

    const v = norm.slice(i, j);
    const hitMax = spec.max && v.length >= spec.max && norm[j] !== GS && j < norm.length;
    segments.push({ ai, value: v, ...(hitMax ? { meta: { max_len_reached: true } } : {}) });

    i = norm[j] === GS ? j + 1 : j;
  }

  return { segments, meta };
}

function parseNonGs1(norm, raw_string, context) {
  const meta = {
    kind: "NON_GS1",
    symbology_hint: null,
    additional_checks: [],
  };

  // Symbology hint from UI context (if provided)
  const hint = context && (context.barcode_format || context.format || context.symbology);
  if (hint) meta.symbology_hint = String(hint);

  // Try to infer from raw symbology identifiers
  const raw = String(raw_string || "");
  const sym = /^\]([A-Za-z0-9]{2})/.exec(raw)?.[1] || null;
  if (sym) meta.symbology_hint = meta.symbology_hint || `]${sym}`;

  // URLs (common in QR)
  if (/^https?:\/\//i.test(norm)) {
    meta.kind = "URI";
    meta.additional_checks.push({ code: "NON_PRODUCT_PAYLOAD_URI", severity: "WARN", message: "Scanned payload is a URL (QR). Not a GS1 product identifier." });
    return { segments: [{ ai: "URI", value: norm }], meta };
  }

  // JSON (common in QR)
  if ((norm.startsWith("{") && norm.endsWith("}")) || (norm.startsWith("[") && norm.endsWith("]"))) {
    try {
      const obj = JSON.parse(norm);
      meta.kind = "JSON";
      meta.additional_checks.push({ code: "NON_PRODUCT_PAYLOAD_JSON", severity: "WARN", message: "Scanned payload is JSON (QR). Not a GS1 product identifier." });
      return { segments: [{ ai: "JSON", value: norm }], meta: { ...meta, json_preview: Array.isArray(obj) ? "array" : "object" } };
    } catch {
      // fall through
    }
  }

  // Pure numeric famous types (EAN/UPC/GTIN/SSCC)
  const nk = guessNumericKind(norm);
  if (nk) {
    if (nk === "SSCC18") {
      meta.kind = "SSCC";
      const segs = [{ ai: "00", value: norm, source: nk }];
      // validate mod10
      if (!isValidMod10(norm)) {
        meta.additional_checks.push({ code: "SSCC_CHECKDIGIT_INVALID", severity: "BLOCK", message: "Invalid SSCC check digit (Mod10)." });
      }
      return { segments: segs, meta };
    }
    // GTIN family
    meta.kind = "GTIN";
    const gtin14 = gtinTo14(norm);
    const segs = [{ ai: "01", value: gtin14, source: nk }];
    // validate mod10 (GTIN check digit) using existing validator
    if (!isValidGtin14(gtin14)) {
      meta.additional_checks.push({ code: "GTIN_CHECKDIGIT_INVALID", severity: "BLOCK", message: "Invalid GTIN check digit (Mod10).", details: { gtin14, source: nk } });
    }
    return { segments: segs, meta };
  }

  // HIBC (healthcare) – best-effort detection
  if (norm.startsWith("+") && /^[\+A-Z0-9\-\.\/\$% ]+$/i.test(norm)) {
    meta.kind = "HIBC";
    meta.additional_checks.push({ code: "HIBC_DETECTED", severity: "WARN", message: "HIBC-like payload detected. Parsed as opaque identifier (best-effort)." });
    return { segments: [{ ai: "HIBC", value: norm }], meta };
  }

  // Default: treat as internal / custom identifier (Code128/Code39/ITF/PDF417/Aztec/etc.)
  meta.kind = "ID";
  meta.additional_checks.push({ code: "NON_GS1_ID", severity: "WARN", message: "Non-GS1 barcode payload. Stored as an opaque identifier." });
  return { segments: [{ ai: "ID", value: norm }], meta };
}

export function parseBarcode(raw_string, policy, context) {
  const normalized = normalizeInput(raw_string);

  // Strong GS1 hints: ASCII GS separator OR symbology identifiers (]C1, ]d2, ]Q3)
  const raw = String(raw_string || "");
  const sym = /^\]([A-Za-z0-9]{2})/.exec(raw)?.[1] || "";
  const symUpper = sym.toUpperCase();
  const strongGs1 = normalized.includes(GS) || ["C1", "D2", "Q3"].includes(symUpper);

  // Also treat strings starting with known AIs as GS1 (with or without separators)
  const startsLikeAI = !!tryMatchAI(normalized, 0);

  if (strongGs1 || startsLikeAI) {
    const gs1 = parseGs1(normalized, policy?.missing_gs_behavior || "BLOCK");
    // attach symbology hint if present
    if (sym) gs1.meta.symbology_hint = `]${sym}`;
    if (context && (context.barcode_format || context.format)) gs1.meta.symbology_hint = gs1.meta.symbology_hint || String(context.barcode_format || context.format);
    return { normalized, ...gs1 };
  }

  const non = parseNonGs1(normalized, raw_string, context);
  return { normalized, segments: non.segments, meta: non.meta };
}

export function decide(parsedResult, policy) {
  const checks = [];
  const parsed = Array.isArray(parsedResult) ? parsedResult : parsedResult?.segments || [];
  const meta = Array.isArray(parsedResult) ? {} : (parsedResult?.meta || {});

  // Extra checks produced by the multi-parser (e.g., URL/JSON/HIBC/non-GS1 hints)
  const preChecks = Array.isArray(meta?.additional_checks) ? meta.additional_checks : [];
  for (const c of preChecks) checks.push(c);

  const map = {};
  for (const p of parsed) {
    if (p.ai !== "??") map[p.ai] = p.value;
  }

  // Numeric-as-GTIN behavior
  if (parsed.some((x) => x.source === "NUMERIC_AS_GTIN") && policy.accept_numeric_as_gtin === false) {
    checks.push({ code: "NUMERIC_GTIN_NOT_ALLOWED", severity: "BLOCK", message: "Numeric-only payload treated as GTIN is disabled by policy." });
  }

  // Missing GS explicit enforcement (matches runbook)
  if (meta.missing_gs_detected) {
    const sev = (policy.missing_gs_behavior || "BLOCK") === "LOOKAHEAD" ? "WARN" : "BLOCK";
    checks.push({
      code: "MISSING_GS_SEPARATOR",
      severity: sev,
      message: sev === "BLOCK" ? "Missing GS (ASCII 29) separator detected. Strict policy blocks this scan." : "Missing GS separator detected. Parsed via lookahead (WARN).",
      details: { fields: meta.missing_gs_fields || [] },
    });
  }

  // Required primary identifier checks (famous/typical barcode families)
  // Default behavior: require GTIN (AI 01), but allow SSCC-only workflows via policy.
  const requireGtin = policy?.require_gtin !== false;           // default true
  const allowSsccOnly = policy?.allow_sscc_only !== false;      // default true

  if (requireGtin && !map["01"]) {
    if (allowSsccOnly && map["00"]) {
      checks.push({ code: "SSCC_ONLY", severity: "WARN", message: "SSCC (AI 00) detected without GTIN (AI 01)." });
    } else {
      checks.push({ code: "REQ_AI_01_MISSING", severity: "BLOCK", message: "Missing GTIN (AI 01)." });
    }
  }

  // SSCC check digit (Mod10) when present
  if (map["00"] && policy?.enforce_sscc_checkdigit !== false) {
    if (!isValidMod10(map["00"])) {
      // Avoid duplication if the parser already added it
      const exists = checks.some((c) => c.code === "SSCC_CHECKDIGIT_INVALID");
      if (!exists) checks.push({ code: "SSCC_CHECKDIGIT_INVALID", severity: "BLOCK", message: "Invalid SSCC check digit (Mod10)." });
    }
  }

  // GTIN check digit

  // GTIN check digit
  if (policy.enforce_gtin_checkdigit !== false && map["01"]) {
    const gtin14 = gtinTo14(map["01"]);
    if (!isValidGtin14(gtin14)) {
      checks.push({ code: "GTIN_CHECKDIGIT_INVALID", severity: "BLOCK", message: "Invalid GTIN check digit for AI 01.", details: { gtin14 } });
    }
  }

  // Expiry
  if (policy.expiry_required && !map["17"]) {
    checks.push({ code: "REQ_AI_17_MISSING", severity: "BLOCK", message: "Missing Expiry (AI 17) per policy." });
  }
  if (map["17"]) {
    const pe = parseExpiryYYMMDD(map["17"]);
    if (pe.error) {
      checks.push({ code: pe.error, severity: "BLOCK", message: "Invalid expiry value for AI 17." });
    } else {
      // expired?
      const today = new Date();
      const exp = new Date(pe.iso + "T00:00:00Z");
      const diffDays = Math.ceil((exp.getTime() - today.getTime()) / (1000 * 60 * 60 * 24));
      if (diffDays < 0) {
        checks.push({ code: "EXPIRY_EXPIRED", severity: "BLOCK", message: "Item is expired (AI 17)." });
      } else {
        const thr = Number(policy.near_expiry_threshold_days ?? 90);
        if (!Number.isNaN(thr) && diffDays <= thr) {
          const sev = (policy.near_expiry_severity || "WARN").toUpperCase() === "BLOCK" ? "BLOCK" : "WARN";
          checks.push({
            code: "EXPIRY_NEAR",
            severity: sev,
            message: `Expiry is within threshold (${thr} days).`,
            details: { expiry_iso: pe.iso, days_left: diffDays, threshold_days: thr },
          });
        }
      }
    }
  }

  // Tracking policy
  const tp = policy.tracking_policy || "LOT_ONLY";
  if ((tp === "LOT_ONLY" || tp === "LOT_AND_SERIAL") && !map["10"]) {
    checks.push({ code: "REQ_AI_10_MISSING", severity: "BLOCK", message: "Missing Lot (AI 10) per policy." });
  }
  if ((tp === "SERIAL_ONLY" || tp === "LOT_AND_SERIAL") && !map["21"]) {
    checks.push({ code: "REQ_AI_21_MISSING", severity: "BLOCK", message: "Missing Serial (AI 21) per policy." });
  }

  if (parsed.some((x) => x.ai === "??")) {
    checks.push({ code: "UNKNOWN_PAYLOAD", severity: "WARN", message: "Unrecognized payload after parsing." });
  }

  const hasBlock = checks.some((c) => c.severity === "BLOCK");
  const decisionRaw = hasBlock ? "BLOCK" : checks.length ? "WARN" : "PASS";

  // ✅ NO-BLOCK mode (default): NEVER return BLOCK. Convert BLOCK → WARN and keep transparency in meta.
  if (NO_BLOCK) {
    const block_codes = checks.filter((c) => c.severity === "BLOCK").map((c) => c.code);
    const checks_nb = checks.map((c) =>
      c.severity === "BLOCK" ? { ...c, severity: "WARN", originally: "BLOCK" } : c
    );
    const decision = decisionRaw === "BLOCK" ? "WARN" : decisionRaw;
    const meta_nb = { ...(meta || {}), no_block: true, would_block: hasBlock, would_block_codes: block_codes };
    return { decision, checks: checks_nb, meta: meta_nb };
  }

  return { decision: decisionRaw, checks, meta };
}

async function getActivePolicy() {
  const r = await q("SELECT config FROM policies WHERE is_active=true ORDER BY version DESC LIMIT 1");
  if (!r.rows.length) {
    return {
      expiry_required: true,
      tracking_policy: "LOT_ONLY",
      missing_gs_behavior: "BLOCK",
      accept_numeric_as_gtin: true,
      enforce_gtin_checkdigit: true,
      near_expiry_threshold_days: 90,
      near_expiry_severity: "WARN",
      allow_commit_on_warn: true,
    };
  }
  return r.rows[0].config;
}

// ---------------- Idempotency ----------------
async function getIdemRecord(key) {
  const r = await q("SELECT key, request_hash, response FROM idempotency WHERE key=$1", [key]);
  return r.rows[0] || null;
}

async function putIdemRecord({ key, request_hash, response }) {
  // Never overwrite if already exists; write once.
  await q(
    `INSERT INTO idempotency (key, request_hash, response)
     VALUES ($1,$2,$3)
     ON CONFLICT (key) DO NOTHING`,
    [key, request_hash, response]
  );
}

// ---------------- Express App ----------------
const _loginBuckets = new Map(); // ip -> {count, resetAt}
function loginRateLimit(req, res, next) {
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown").toString().split(",")[0].trim();
  const now = Date.now();
  const windowMs = 10 * 60 * 1000; // 10 min
  const maxAttempts = 30; // generous for pilot
  let b = _loginBuckets.get(ip);
  if (!b || now > b.resetAt) {
    b = { count: 0, resetAt: now + windowMs };
    _loginBuckets.set(ip, b);
  }
  b.count += 1;
  if (b.count > maxAttempts) {
    return res.status(429).json({ error: "TOO_MANY_LOGIN_ATTEMPTS", retry_after_seconds: Math.ceil((b.resetAt - now)/1000) });
  }
  return next();
}

// Parse/Validate rate limiting
const _parseBuckets = new Map(); // ip -> {count, resetAt}
function parseRateLimit(req, res, next) {
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown").toString().split(",")[0].trim();
  const now = Date.now();
  const windowMs = 1 * 60 * 1000; // 1 min
  const maxAttempts = 100; // 100 scans per minute
  let b = _parseBuckets.get(ip);
  if (!b || now > b.resetAt) {
    b = { count: 0, resetAt: now + windowMs };
    _parseBuckets.set(ip, b);
  }
  b.count += 1;
  if (b.count > maxAttempts) {
    return res.status(429).json({ error: "TOO_MANY_SCAN_REQUESTS", retry_after_seconds: Math.ceil((b.resetAt - now)/1000) });
  }
  return next();
}


// ---------------- ZXing (same-origin vendor script) ----------------
// Goal: the browser NEVER needs to reach a public CDN. It only loads ZXing from:
//   GET /vendor/zxing-umd.min.js   (same-origin)
// The server will fetch + cache the UMD bundle from multiple sources (first success wins).
const ZXING_UMD_URLS = [
  "https://cdn.jsdelivr.net/npm/@zxing/browser@0.1.1/umd/index.min.js",
  "https://unpkg.com/@zxing/browser@0.1.1/umd/index.min.js",
];

let _ZXING_CACHE = null;
let _ZXING_ETAG = null;
let _ZXING_FETCHING = null;

async function fetchTextWithTimeout(url, ms = 9000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    const r = await fetch(url, { signal: ctrl.signal, headers: { "User-Agent": "gs1hub-server" } });
    if (!r.ok) throw new Error(`ZXing fetch failed: ${r.status} ${r.statusText}`);
    return await r.text();
  } finally {
    clearTimeout(t);
  }
}

async function getZXingUmd() {
  if (_ZXING_CACHE) return { code: _ZXING_CACHE, etag: _ZXING_ETAG };
  if (_ZXING_FETCHING) return _ZXING_FETCHING;

  _ZXING_FETCHING = (async () => {
    let lastErr = null;
    // Prefer a bundled local copy if you place it at: public/vendor/zxing-umd.min.js
    // This makes the app work even in restricted egress environments.
    try {
      const localPath = path.join(__dirname, "public", "vendor", "zxing-umd.min.js");
      if (fs.existsSync(localPath)) {
        const code = fs.readFileSync(localPath, "utf8");
        if (code && code.length >= 50_000) {
          _ZXING_CACHE = code;
          _ZXING_ETAG = sha256Hex(code);
          console.log("[ZXing] using local vendor file:", localPath);
          return { code: _ZXING_CACHE, etag: _ZXING_ETAG };
        }
      }
    } catch (e) {
      // ignore
    }

    for (const url of ZXING_UMD_URLS) {
      try {
        const code = await fetchTextWithTimeout(url);
        // Sanity check: real bundle is large
        if (!code || code.length < 50_000) throw new Error("ZXing bundle too small / invalid");
        _ZXING_CACHE = code;
        _ZXING_ETAG = sha256Hex(code);
        console.log("[ZXing] cached UMD from:", url);
        return { code: _ZXING_CACHE, etag: _ZXING_ETAG };
      } catch (e) {
        lastErr = e;
        console.warn("[ZXing] source failed:", url, e?.message || e);
      }
    }
    throw lastErr || new Error("ZXing fetch failed from all sources");
  })();

  try {
    return await _ZXING_FETCHING;
  } finally {
    _ZXING_FETCHING = null;
  }
}

export function createApp() {
  const app = express();
app.disable("x-powered-by");
// Basic security headers (no external deps)
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(self), microphone=(), geolocation=()");
  // CSP: allow self + blob for camera preview; allow inline styles/scripts for the single-file UI.
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'; base-uri 'self'"
  );
  if (req.secure) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  next();
});


  app.use(
    cors({
      origin: function (origin, cb) {
        if (!origin) return cb(null, true);
        if (ALLOWED_ORIGINS.length === 0) return cb(null, true);
        if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
        return cb(new Error("CORS blocked"), false);
      },
      credentials: true,
    })
  );

  app.use(express.json({ limit: "2mb" }));

  // ---------------- API ----------------
  app.get("/api/health", (req, res) =>
    res.json({ status: "ok", time: nowIso(), bc_mode: BC_MODE, has_db: !!DATABASE_URL })
  );

  // Serve ZXing bundle from same-origin (client never hits a CDN).
  app.get("/vendor/zxing-umd.min.js", async (req, res) => {
    try {
      const { code, etag } = await getZXingUmd();
      if (req.headers["if-none-match"] === etag) return res.status(304).end();
      res.setHeader("Content-Type", "application/javascript; charset=utf-8");
      res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
      res.setHeader("ETag", etag);
      return res.send(code);
    } catch (e) {
      const msg = (e?.message || String(e)).replace(/\n/g, " ");
      res.status(503);
      res.setHeader("Content-Type", "application/javascript; charset=utf-8");
      return res.send(`/* ZXing unavailable (server could not fetch it): ${msg} */\n`);
    }
  });


  app.get("/api/integration/status", auth, requireRole("admin"), async (req, res) => {
    res.json({
      bc_mode: BC_MODE,
      bc_base_url_set: !!BC_BASE_URL,
      bc_company_id_set: !!BC_COMPANY_ID,
    });
  });

  app.post("/api/auth/login", loginRateLimit, async (req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Missing username/password" });

    const r = await q("SELECT id, username, password_hash, role, is_active FROM users WHERE username=$1", [
      username,
    ]);
    if (!r.rows.length) return res.status(401).json({ error: "Invalid credentials" });
    const row = r.rows[0];
    if (!row.is_active) return res.status(403).json({ error: "Account disabled" });
    if (!bcrypt.compareSync(password, row.password_hash)) return res.status(401).json({ error: "Invalid credentials" });

    const u = { id: row.id, username: row.username, role: row.role };
    const token = signToken(u);

    await audit({
      actor: u,
      event_type: "AUTH_LOGIN",
      entity_type: "user",
      entity_id: row.id,
      payload: { username: row.username, role: row.role },
    });

    res.json({ token, user: u });
  });

  app.get("/api/auth/me", auth, (req, res) => {
    res.json({ user: { id: req.user.sub, username: req.user.username, role: req.user.role } });
  });

  app.post("/api/scans/parse-validate", parseRateLimit, auth, requireRole("operator", "admin"), async (req, res) => {
    const idem = req.header("Idempotency-Key");
    if (!idem) return res.status(400).json({ error: "Missing Idempotency-Key" });

    const { scan_id, raw_string, context } = req.body || {};
    if (!scan_id || !raw_string || !context)
      return res.status(400).json({ error: "scan_id, raw_string, context are required" });

    const request_hash = hashPayload({ scan_id, raw_string, context });

    const cached = await getIdemRecord(idem);
    if (cached) {
      if (cached.request_hash && cached.request_hash !== request_hash) {
        return res.status(409).json({ error: "IDEMPOTENCY_CONFLICT" });
      }
      return res.json(cached.response);
    }

    const policy = await getActivePolicy();
    const parsedBundle = parseBarcode(raw_string, policy, context);
    const normalized = parsedBundle.normalized;
    const { decision, checks, meta } = decide(parsedBundle, policy);

    const resp = {
      scan_id,
      decision,
      normalized,
      parsed: parsedBundle.segments,
      parse_meta: meta,
      checks,
      policy_applied: policy,
    };

    const scanRowId = `SCAN-${scan_id}`;
    await q(
      `
      INSERT INTO scans (id, scan_id, raw_string, normalized, decision, checks, parsed, context)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      ON CONFLICT (id) DO UPDATE SET
        raw_string=EXCLUDED.raw_string,
        normalized=EXCLUDED.normalized,
        decision=EXCLUDED.decision,
        checks=EXCLUDED.checks,
        parsed=EXCLUDED.parsed,
        context=EXCLUDED.context
    `,
      [scanRowId, scan_id, raw_string, normalized, decision, checks, parsedBundle.segments, context]
    );

    await putIdemRecord({ key: idem, request_hash, response: resp });

    await audit({
      actor: { username: req.user.username, role: req.user.role },
      event_type: "SCAN_PARSE_VALIDATE",
      entity_type: "scan",
      entity_id: scanRowId,
      payload: { scan_id, decision, checks_count: checks.length, template: context?.template || null },
    });

    res.json(resp);
  });

  // Commit workflow (SIMULATED/LIVE). Purchase Receipt then Transfer.
  app.post("/api/postings/commit", auth, requireRole("operator", "admin"), async (req, res) => {
    const idem = req.header("Idempotency-Key");
    if (!idem) return res.status(400).json({ error: "Missing Idempotency-Key" });

    const { scan_id, posting_intent, context } = req.body || {};
    if (!scan_id || !posting_intent || !context) {
      return res.status(400).json({ error: "scan_id, posting_intent, context are required" });
    }

    const pi = String(posting_intent).toUpperCase();
    if (!["PURCHASE_RECEIPT", "TRANSFER_RECEIPT"].includes(pi)) {
      return res.status(400).json({ error: "posting_intent must be PURCHASE_RECEIPT or TRANSFER_RECEIPT" });
    }

// Business-level de-duplication: one commit per (scan_id, posting_intent)
const existing = await q("SELECT response FROM bc_postings WHERE scan_id=$1 AND posting_intent=$2 ORDER BY created_at DESC LIMIT 1", [scan_id, pi]);
if (existing.rows.length) {
  return res.json({ ...existing.rows[0].response, dedupe: "BUSINESS_KEY" });
}

    const request_hash = hashPayload({ scan_id, posting_intent: pi, context });
    const cached = await getIdemRecord(idem);
    if (cached) {
      if (cached.request_hash && cached.request_hash !== request_hash) {
        return res.status(409).json({ error: "IDEMPOTENCY_CONFLICT" });
      }
      return res.json(cached.response);
    }

    // Require that scan exists and is not BLOCK (unless admin overrides)
    const scanRowId = `SCAN-${scan_id}`;
    const scanR = await q("SELECT decision, parsed, checks, context FROM scans WHERE id=$1", [scanRowId]);
    if (!scanR.rows.length) return res.status(404).json({ error: "SCAN_NOT_FOUND" });

    const scan = scanR.rows[0];
    const policy = await getActivePolicy();

// ✅ NO-BLOCK: never stop commit because of scan decision.
// We keep checks as warnings so the operator can see WHY it was flagged.
const commit_warnings = Array.isArray(scan.checks) ? scan.checks : [];

    // Simulated BC result
    const simulatedDocNo = `SIM-${pi === "PURCHASE_RECEIPT" ? "PR" : "TR"}-${new Date().getFullYear()}-${String(
      Math.floor(Math.random() * 1000000)
    ).padStart(6, "0")}`;

    const response = {
      ok: true,
      warnings: commit_warnings,
      mode: BC_MODE,
      scan_id,
      posting_intent: pi,
      bc_result: {
        status: BC_MODE === "LIVE" ? "PENDING" : "SIMULATED_OK",
        document_no: simulatedDocNo,
      },
      correlation_id: uuid(),
      notes:
        BC_MODE === "LIVE"
          ? "BC_MODE=LIVE not implemented in this starter. Wire BC APIs in /api/postings/commit."
          : "SIMULATED commit. Wire BC APIs later.",
    };

    // Store idempotency response + bc_postings
    await putIdemRecord({ key: idem, request_hash, response });

    try {
  await q(
    `INSERT INTO bc_postings (id, scan_id, posting_intent, idempotency_key, request_hash, status, response, actor_username)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [uuid(), scan_id, pi, idem, request_hash, response.bc_result.status, response, req.user.username]
  );
} catch (e) {
  // If unique business-key is violated, return the existing response (safe idempotent behavior)
  const ex = await q("SELECT response FROM bc_postings WHERE scan_id=$1 AND posting_intent=$2 ORDER BY created_at DESC LIMIT 1", [scan_id, pi]);
  if (ex.rows.length) return res.json({ ...ex.rows[0].response, dedupe: "UNIQUE_INDEX" });
  throw e;
}


    await audit({
      actor: { username: req.user.username, role: req.user.role },
      event_type: "BC_COMMIT_REQUEST",
      entity_type: "bc_posting",
      entity_id: scan_id,
      payload: { posting_intent: pi, status: response.bc_result.status, document_no: simulatedDocNo },
    });

    res.json(response);
  });

  // ---------------- Cases ----------------
  app.post("/api/cases", auth, requireRole("operator", "admin"), async (req, res) => {
    const { scan_id, raw_string, decision, checks, context } = req.body || {};
    if (!scan_id || !raw_string || !decision || !Array.isArray(checks) || !context) {
      return res.status(400).json({ error: "scan_id, raw_string, decision, checks[], context required" });
    }
let dc = String(decision || "WARN").toUpperCase();
if (NO_BLOCK && dc === "BLOCK") dc = "WARN";
if (!["WARN", "BLOCK"].includes(dc)) dc = "WARN";

    const id = `CASE-${new Date().getFullYear()}-${String(Math.floor(Math.random() * 1000000)).padStart(6, "0")}`;
    await q(
      `
      INSERT INTO cases (id, status, decision, scan_id, user_id, raw_string, checks, context)
      VALUES ($1,'NEW',$2,$3,$4,$5,$6,$7)
    `,
      [id, dc, scan_id, req.user.username, raw_string, checks, context]
    );

    await audit({
      actor: { username: req.user.username, role: req.user.role },
      event_type: "CASE_CREATED",
      entity_type: "case",
      entity_id: id,
      payload: { scan_id, decision: dc, checks_count: checks.length },
    });

    res.status(201).json({ id, status: "NEW", decision: dc, created_at: nowIso() });
  });

  app.get("/api/cases", auth, async (req, res) => {
  const { status, decision, mine, case_id, q: qtext } = req.query || {};
  const params = [];
  let idx = 1;
  let where = "WHERE 1=1";

  if (case_id) { where += ` AND id=$${idx++}`; params.push(case_id); }
  if (status) { where += ` AND status=$${idx++}`; params.push(status); }
  if (decision) { where += ` AND decision=$${idx++}`; params.push(decision); }

  // Search text in raw payload or scan_id
  if (qtext) {
    where += ` AND (raw_string ILIKE $${idx++} OR scan_id ILIKE $${idx++})`;
    const like = `%${String(qtext)}%`;
    params.push(like, like);
  }

  // Non-admin users see only their own cases
  if (req.user.role !== "admin") {
    where += ` AND user_id=$${idx++}`; params.push(req.user.username);
  } else if (mine === "1") {
    where += ` AND user_id=$${idx++}`; params.push(req.user.username);
  }

  const r = await q(
    `
    SELECT 
      id, created_at, status, decision, scan_id, user_id,
      raw_string AS raw,
      checks::text AS checks,
      context,
      comment,
      resolution
    FROM cases
    ${where}
    ORDER BY created_at DESC
    LIMIT 200
  `,
    params
  );

  res.json(r.rows);
});

// GET /api/cases/:id - Fetch single case (UI)
app.get("/api/cases/:case_id", auth, async (req, res) => {
  const { case_id } = req.params;
  const r = await q("SELECT * FROM cases WHERE id=$1", [case_id]);
  if (!r.rows.length) return res.status(404).json({ error: "Case not found" });
  // Non-admin cannot access others' cases
  if (req.user.role !== "admin" && r.rows[0].user_id !== req.user.username) {
    return res.status(403).json({ error: "Forbidden" });
  }
  res.json(r.rows[0]);
});

app.patch("/api/cases/:case_id", auth, requireRole("admin"), async (req, res) => {
    const { case_id } = req.params;
    const { status, comment, resolution } = req.body || {};

    const r0 = await q("SELECT id FROM cases WHERE id=$1", [case_id]);
    if (!r0.rows.length) return res.status(404).json({ error: "Case not found" });

    await q(
      `
      UPDATE cases
      SET status=COALESCE($2,status),
          comment=COALESCE($3,comment),
          resolution=COALESCE($4,resolution)
      WHERE id=$1
    `,
      [case_id, status, comment, resolution]
    );

    await audit({
      actor: { username: req.user.username, role: req.user.role },
      event_type: "CASE_UPDATED",
      entity_type: "case",
      entity_id: case_id,
      payload: { status, has_comment: !!comment, has_resolution: !!resolution },
    });

    const r = await q("SELECT * FROM cases WHERE id=$1", [case_id]);
    res.json(r.rows[0]);
  });

  // ---------------- Dashboard ----------------
  // UI Dashboard (legacy): return {total, pass, warn, block}
app.get("/api/admin/dashboard", auth, requireRole("admin"), async (req, res) => {
  const total = (await q("SELECT COUNT(*)::int AS c FROM scans WHERE created_at >= now() - interval '24 hours'")).rows[0].c;
  const pass = (await q("SELECT COUNT(*)::int AS c FROM scans WHERE decision='PASS' AND created_at >= now() - interval '24 hours'")).rows[0].c;
  const warn = (await q("SELECT COUNT(*)::int AS c FROM scans WHERE decision='WARN' AND created_at >= now() - interval '24 hours'")).rows[0].c;
  const block = (await q("SELECT COUNT(*)::int AS c FROM scans WHERE decision='BLOCK' AND created_at >= now() - interval '24 hours'")).rows[0].c;
  res.json({ total, pass, warn, block });
});

app.get("/api/dashboard/summary", auth, requireRole("admin"), async (req, res) => {
    const total = (await q("SELECT COUNT(*)::int AS c FROM scans WHERE created_at >= now() - interval '24 hours'")).rows[0].c;
    const pass = (await q("SELECT COUNT(*)::int AS c FROM scans WHERE decision='PASS' AND created_at >= now() - interval '24 hours'")).rows[0].c;
    const warn = (await q("SELECT COUNT(*)::int AS c FROM scans WHERE decision='WARN' AND created_at >= now() - interval '24 hours'")).rows[0].c;
    const block = (await q("SELECT COUNT(*)::int AS c FROM scans WHERE decision='BLOCK' AND created_at >= now() - interval '24 hours'")).rows[0].c;

    const rr = await q(`
      SELECT jsonb_array_elements(checks) AS c
      FROM scans
      WHERE decision='BLOCK' AND created_at >= now() - interval '24 hours'
    `);
    const counts = new Map();
    for (const row of rr.rows) {
      const c = row.c;
      if (c && c.severity === "BLOCK") counts.set(c.code, (counts.get(c.code) || 0) + 1);
    }
    const top = [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 7)
      .map(([code, count]) => ({ code, count }));

    res.json({ total_scans_24h: total, pass_24h: pass, warn_24h: warn, block_24h: block, top_block_reasons: top });
  });

  // ---------------- Admin: Users ----------------
  app.get("/api/admin/users", auth, requireRole("admin"), async (req, res) => {
    const r = await q("SELECT id, username, role, is_active, created_at FROM users ORDER BY created_at DESC LIMIT 200");
    res.json(r.rows.map(u => ({ username: u.username, role: u.role, created_at: u.created_at, status: u.is_active ? "ACTIVE" : "DISABLED" })));
  });

  app.post("/api/admin/users", auth, requireRole("admin"), async (req, res) => {
    const { username, password, role } = req.body || {};
    if (!username || !password || !role) return res.status(400).json({ error: "username, password, role required" });
    if (!["operator", "admin", "auditor"].includes(role)) return res.status(400).json({ error: "invalid role" });

    const id = uuid();
    try {
      await q("INSERT INTO users (id, username, password_hash, role, is_active) VALUES ($1,$2,$3,$4,true)", [
        id,
        String(username).trim(),
        bcrypt.hashSync(String(password), 10),
        role,
      ]);

      await audit({
        actor: { username: req.user.username, role: req.user.role },
        event_type: "USER_CREATED",
        entity_type: "user",
        entity_id: id,
        payload: { username: String(username).trim(), role },
      });

      res.status(201).json({ id, username, role, is_active: true });
    } catch {
      return res.status(409).json({ error: "username already exists" });
    }
  });

  app.patch("/api/admin/users/:id", auth, requireRole("admin"), async (req, res) => {
    const { id } = req.params;
    const { role, password, is_active } = req.body || {};

    const r0 = await q("SELECT id, username FROM users WHERE id=$1", [id]);
    if (!r0.rows.length) return res.status(404).json({ error: "User not found" });

    if (role && !["operator", "admin", "auditor"].includes(role)) return res.status(400).json({ error: "invalid role" });

    const sets = [];
    const params = [id];
    let idx = 2;

    if (role) { sets.push(`role=$${idx++}`); params.push(role); }
    if (typeof is_active === "boolean") { sets.push(`is_active=$${idx++}`); params.push(is_active); }
    if (password) { sets.push(`password_hash=$${idx++}`); params.push(bcrypt.hashSync(String(password), 10)); }

    if (!sets.length) return res.status(400).json({ error: "no changes" });

    await q(`UPDATE users SET ${sets.join(", ")} WHERE id=$1`, params);

    await audit({
      actor: { username: req.user.username, role: req.user.role },
      event_type: "USER_UPDATED",
      entity_type: "user",
      entity_id: id,
      payload: { role: role || null, is_active: typeof is_active === "boolean" ? is_active : null, password_changed: !!password },
    });

    const r = await q("SELECT id, username, role, is_active, created_at FROM users WHERE id=$1", [id]);
    res.json(r.rows[0]);
  });// UI users endpoints
app.get("/api/users", auth, requireRole("admin"), async (req, res) => {
  const r = await q("SELECT id, username, role, is_active, created_at FROM users ORDER BY created_at DESC LIMIT 200");
  res.json(r.rows.map(u => ({ username: u.username, role: u.role, created_at: u.created_at, status: u.is_active ? "ACTIVE" : "DISABLED" })));
});

app.post("/api/users", auth, requireRole("admin"), async (req, res) => {
  // Reuse the same logic as /api/admin/users
  const { username, password, role } = req.body || {};
  if (!username || !password || !role) return res.status(400).json({ error: "username, password, role required" });
  if (!["operator", "admin", "auditor"].includes(role)) return res.status(400).json({ error: "invalid role" });

  const id = uuid();
  try {
    await q("INSERT INTO users (id, username, password_hash, role, is_active) VALUES ($1,$2,$3,$4,true)", [
      id,
      String(username).trim(),
      bcrypt.hashSync(String(password), 10),
      role,
    ]);

    await audit({
      actor: { username: req.user.username, role: req.user.role },
      event_type: "USER_CREATED",
      entity_type: "user",
      entity_id: id,
      payload: { username: String(username).trim(), role },
    });

    res.status(201).json({ id, username: String(username).trim(), role, is_active: true });
  } catch (e) {
    if (String(e?.message || "").includes("duplicate")) {
      return res.status(409).json({ error: "username already exists" });
    }
    console.error(e);
    res.status(500).json({ error: "internal error" });
  }
});



  // ---------------- Admin: GTIN Map ----------------
  app.get("/api/gtin-map", auth, requireRole("admin"), async (req, res) => {
    const { search } = req.query || {};
    let where = "WHERE 1=1";
    const params = [];
    let idx = 1;
    if (search) {
      where += ` AND (gtin ILIKE $${idx} OR item_no ILIKE $${idx})`;
      params.push(`%${search}%`);
      idx++;
    }
    const r = await q(
      `SELECT gtin, item_no, uom, status, updated_at FROM gtin_map ${where} ORDER BY updated_at DESC LIMIT 200`,
      params
    );
    res.json({ items: r.rows });
  });

  app.post("/api/gtin-map", auth, requireRole("admin"), async (req, res) => {
    const { gtin, item_no, uom, status } = req.body || {};
    if (!gtin || !item_no) return res.status(400).json({ error: "gtin and item_no required" });
    const st = status ? String(status) : "ACTIVE";
    const r = await q(
      `
      INSERT INTO gtin_map (gtin, item_no, uom, status, updated_at)
      VALUES ($1,$2,$3,$4, now())
      ON CONFLICT (gtin) DO UPDATE SET
        item_no=EXCLUDED.item_no,
        uom=EXCLUDED.uom,
        status=EXCLUDED.status,
        updated_at=now()
      RETURNING gtin, item_no, uom, status, updated_at
    `,
      [String(gtin), String(item_no), uom ? String(uom) : null, st]
    );

    await audit({
      actor: { username: req.user.username, role: req.user.role },
      event_type: "GTIN_MAP_UPSERT",
      entity_type: "gtin_map",
      entity_id: String(gtin),
      payload: { gtin: String(gtin), item_no: String(item_no), status: st },
    });

    res.status(201).json(r.rows[0]);
  });
// UI alias: /api/gtin-map/upsert expects {gtin, itemNo}
app.post("/api/gtin-map/upsert", auth, requireRole("admin"), async (req, res) => {
  const gtin = String(req.body?.gtin ?? "").trim();
  const item_no = String(req.body?.itemNo ?? req.body?.item_no ?? "").trim();
  if (!gtin || !item_no) return res.status(400).json({ error: "gtin and itemNo required" });
  const r = await q(
    `
    INSERT INTO gtin_map (gtin, item_no, uom, status, updated_at)
    VALUES ($1,$2,NULL,'ACTIVE', now())
    ON CONFLICT (gtin) DO UPDATE SET
      item_no=EXCLUDED.item_no,
      status=EXCLUDED.status,
      updated_at=now()
    RETURNING gtin, item_no, uom, status, updated_at
  `,
    [gtin, item_no]
  );

  await audit({
    actor: { username: req.user.username, role: req.user.role },
    event_type: "GTIN_MAP_UPSERT",
    entity_type: "gtin_map",
    entity_id: gtin,
    payload: { gtin, item_no },
  });

  res.json(r.rows[0]);
});



  app.patch("/api/gtin-map/:gtin", auth, requireRole("admin"), async (req, res) => {
    const { gtin } = req.params;
    const { item_no, uom, status } = req.body || {};
    const r0 = await q("SELECT gtin FROM gtin_map WHERE gtin=$1", [gtin]);
    if (!r0.rows.length) return res.status(404).json({ error: "GTIN not found" });

    const sets = [];
    const params = [gtin];
    let idx = 2;
    if (item_no) { sets.push(`item_no=$${idx++}`); params.push(String(item_no)); }
    if (uom !== undefined) { sets.push(`uom=$${idx++}`); params.push(uom === null ? null : String(uom)); }
    if (status) { sets.push(`status=$${idx++}`); params.push(String(status)); }
    sets.push("updated_at=now()");

    await q(`UPDATE gtin_map SET ${sets.join(", ")} WHERE gtin=$1`, params);

    await audit({
      actor: { username: req.user.username, role: req.user.role },
      event_type: "GTIN_MAP_UPDATE",
      entity_type: "gtin_map",
      entity_id: String(gtin),
      payload: { item_no: item_no || null, status: status || null },
    });

    const r = await q("SELECT gtin, item_no, uom, status, updated_at FROM gtin_map WHERE gtin=$1", [gtin]);
    res.json(r.rows[0]);
  });

  // ---------------- Policies ----------------
  app.get("/api/policies/active", auth, requireRole("admin"), async (req, res) => {
    res.json({ policy: await getActivePolicy() });
  });

  app.post("/api/policies/active", auth, requireRole("admin"), async (req, res) => {
    const cfg = req.body || {};
    const next = {
      expiry_required: !!cfg.expiry_required,
      tracking_policy: String(cfg.tracking_policy || "LOT_ONLY"),
      missing_gs_behavior: String(cfg.missing_gs_behavior || "BLOCK"),
      accept_numeric_as_gtin: cfg.accept_numeric_as_gtin !== false,
      allow_commit_on_warn: cfg.allow_commit_on_warn !== false,
    };

    await q("UPDATE policies SET is_active=false WHERE is_active=true");
    const prev = (await q("SELECT COALESCE(MAX(version),0)::int AS v FROM policies")).rows[0].v;
    await q("INSERT INTO policies (id, name, version, is_active, config) VALUES ($1,$2,$3,true,$4)", [
      uuid(),
      "Active Policy",
      prev + 1,
      next,
    ]);

    await audit({
      actor: { username: req.user.username, role: req.user.role },
      event_type: "POLICY_ACTIVATED",
      entity_type: "policy",
      entity_id: String(prev + 1),
      payload: next,
    });

    res.json({ ok: true, policy: next, version: prev + 1 });
  });

  // ---------------- Audit listing ----------------
  app.get("/api/audit", auth, requireRole("admin", "auditor"), async (req, res) => {
    const { event_type, actor_username } = req.query || {};
    const params = [];
    let idx = 1;
    let where = "WHERE 1=1";

    if (event_type) { where += ` AND event_type=$${idx++}`; params.push(String(event_type)); }
    if (actor_username) { where += ` AND actor_username=$${idx++}`; params.push(String(actor_username)); }

    const r = await q(
      `
      SELECT id, created_at, actor_username, actor_role, event_type, entity_type, entity_id, payload
      FROM audit_events
      ${where}
      ORDER BY created_at DESC
      LIMIT 200
    `,
      params
    );
    res.json({ items: r.rows });
  });

  // ============================================================================
  // NEW APIs - Added below existing endpoints
  // ============================================================================

  // ----------------------------------------------------------------------------
  // 1) Items Cache APIs
  // ----------------------------------------------------------------------------

  // GET /api/items-cache - Get all items
  app.get('/api/items-cache', auth, requireRole('operator', 'admin'), async (req, res) => {
    try {
      const result = await q(
        'SELECT item_no, item_name, is_top200, updated_at FROM public.items_cache ORDER BY item_name',
        []
      );
      res.json({ ok: true, items: result.rows });
    } catch (e) {
      console.error('items-cache error:', e);
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // GET /api/items-cache/top200 - Get Top 200 items only
  app.get('/api/items-cache/top200', auth, requireRole('operator', 'admin'), async (req, res) => {
    try {
      const result = await q(
        'SELECT item_no, item_name FROM public.items_cache WHERE is_top200 = true ORDER BY item_name',
        []
      );
      res.json({ ok: true, items: result.rows });
    } catch (e) {
      console.error('items-cache/top200 error:', e);
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // POST /api/items-cache/sync - Sync from BC (admin only, placeholder)
  app.post('/api/items-cache/sync', auth, requireRole('admin'), async (req, res) => {
    try {
      await audit({
        actor: { username: req.user.username, role: req.user.role },
        event_type: 'ITEMS_CACHE_SYNC_REQUESTED',
        entity_type: 'SYSTEM',
        entity_id: 'items_cache',
        payload: { bc_mode: BC_MODE }
      });
      
      res.json({
        ok: true,
        message: 'Sync requested. Feature available in BC LIVE mode.',
        bc_mode: BC_MODE
      });
    } catch (e) {
      console.error('items-cache/sync error:', e);
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // ----------------------------------------------------------------------------
  // 2) Work Sessions APIs
  // ----------------------------------------------------------------------------

  // POST /api/work-sessions - Create new session (admin)
  app.post('/api/work-sessions', auth, requireRole('admin'), async (req, res) => {
    try {
      const { session_type, reference_no } = req.body;
      if (!session_type) {
        return res.status(400).json({ ok: false, error: 'MISSING_SESSION_TYPE' });
      }
      
      const result = await q(
        `INSERT INTO public.work_sessions (session_type, reference_no, created_by, status)
         VALUES ($1, $2, $3, 'OPEN')
         RETURNING id, session_type, reference_no, status, created_at`,
        [session_type, reference_no || null, req.user.username]
      );
      
      await audit({
        actor: { username: req.user.username, role: req.user.role },
        event_type: 'WORK_SESSION_CREATED',
        entity_type: 'SESSION',
        entity_id: result.rows[0].id,
        payload: { session_type, reference_no }
      });
      
      res.json({ ok: true, session: result.rows[0] });
    } catch (e) {
      console.error('work-sessions create error:', e);
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // GET /api/work-sessions - List all sessions
  app.get('/api/work-sessions', auth, requireRole('operator', 'admin'), async (req, res) => {
    try {
      const { status } = req.query;
      let query = 'SELECT * FROM public.work_sessions';
      const params = [];
      
      if (status) {
        query += ' WHERE status = $1';
        params.push(status);
      }
      
      query += ' ORDER BY created_at DESC LIMIT 50';
      
      const result = await q(query, params);
      res.json({ ok: true, sessions: result.rows });
    } catch (e) {
      console.error('work-sessions list error:', e);
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // GET /api/work-sessions/:id - Get session details
  app.get('/api/work-sessions/:id', auth, requireRole('operator', 'admin'), async (req, res) => {
    try {
      const { id } = req.params;
      const result = await q(
        'SELECT * FROM public.work_sessions WHERE id = $1',
        [id]
      );
      
      if (result.rows.length === 0) {
        return res.status(404).json({ ok: false, error: 'SESSION_NOT_FOUND' });
      }
      
      res.json({ ok: true, session: result.rows[0] });
    } catch (e) {
      console.error('work-sessions get error:', e);
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // PATCH /api/work-sessions/:id/close - Close session (admin)
  app.patch('/api/work-sessions/:id/close', auth, requireRole('admin'), async (req, res) => {
    try {
      const { id } = req.params;
      const result = await q(
        `UPDATE public.work_sessions 
         SET status = 'CLOSED', closed_at = NOW()
         WHERE id = $1 AND status = 'OPEN'
         RETURNING *`,
        [id]
      );
      
      if (result.rows.length === 0) {
        return res.status(404).json({ ok: false, error: 'SESSION_NOT_FOUND_OR_ALREADY_CLOSED' });
      }
      
      await audit({
        actor: { username: req.user.username, role: req.user.role },
        event_type: 'WORK_SESSION_CLOSED',
        entity_type: 'SESSION',
        entity_id: id,
        payload: {}
      });
      
      res.json({ ok: true, session: result.rows[0] });
    } catch (e) {
      console.error('work-sessions close error:', e);
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // POST /api/work-sessions/:id/lines - Add expected lines
  app.post('/api/work-sessions/:id/lines', auth, requireRole('admin'), async (req, res) => {
    try {
      const { id } = req.params;
      const { lines } = req.body; // Array of { item_no, expected_qty }
      
      if (!Array.isArray(lines) || lines.length === 0) {
        return res.status(400).json({ ok: false, error: 'MISSING_LINES' });
      }
      
      const inserted = [];
      for (const line of lines) {
        const { item_no, expected_qty } = line;
        if (!item_no || !expected_qty || expected_qty <= 0) {
          continue;
        }
        
        const result = await q(
          `INSERT INTO public.work_lines (session_id, item_no, expected_qty)
           VALUES ($1, $2, $3)
           ON CONFLICT (session_id, item_no) 
           DO UPDATE SET expected_qty = EXCLUDED.expected_qty, updated_at = NOW()
           RETURNING *`,
          [id, item_no, expected_qty]
        );
        
        inserted.push(result.rows[0]);
      }
      
      await audit({
        actor: { username: req.user.username, role: req.user.role },
        event_type: 'WORK_LINES_ADDED',
        entity_type: 'SESSION',
        entity_id: id,
        payload: { count: inserted.length }
      });
      
      res.json({ ok: true, lines: inserted });
    } catch (e) {
      console.error('work-lines add error:', e);
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // GET /api/work-sessions/:id/lines - Get session lines with progress
  app.get('/api/work-sessions/:id/lines', auth, requireRole('operator', 'admin'), async (req, res) => {
    try {
      const { id } = req.params;
      const result = await q(
        `SELECT 
           wl.*,
           ic.item_name,
           GREATEST(wl.expected_qty - wl.scanned_qty, 0) AS remaining_qty
         FROM public.work_lines wl
         LEFT JOIN public.items_cache ic ON ic.item_no = wl.item_no
         WHERE wl.session_id = $1
         ORDER BY wl.item_no`,
        [id]
      );
      
      res.json({ ok: true, lines: result.rows });
    } catch (e) {
      console.error('work-lines get error:', e);
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // PATCH /api/work-sessions/:id/lines/:line_id - Update scanned qty
  app.patch('/api/work-sessions/:id/lines/:line_id', auth, requireRole('operator', 'admin'), async (req, res) => {
    try {
      const { id, line_id } = req.params;
      const { scanned_qty } = req.body;
      
      if (scanned_qty === undefined || scanned_qty < 0) {
        return res.status(400).json({ ok: false, error: 'INVALID_SCANNED_QTY' });
      }
      
      const result = await q(
        `UPDATE public.work_lines 
         SET scanned_qty = $1, updated_at = NOW()
         WHERE id = $2 AND session_id = $3
         RETURNING *`,
        [scanned_qty, line_id, id]
      );
      
      if (result.rows.length === 0) {
        return res.status(404).json({ ok: false, error: 'LINE_NOT_FOUND' });
      }
      
      res.json({ ok: true, line: result.rows[0] });
    } catch (e) {
      console.error('work-lines update error:', e);
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // ----------------------------------------------------------------------------
  // 3) Quantity Suggestion API
  // ----------------------------------------------------------------------------

  // GET /api/qty-suggestion?session_id=xxx&item_no=yyy
  app.get('/api/qty-suggestion', auth, requireRole('operator', 'admin'), async (req, res) => {
    try {
      const { session_id, item_no } = req.query;
      
      if (!session_id || !item_no) {
        return res.status(400).json({ ok: false, error: 'MISSING_PARAMETERS' });
      }
      
      const result = await q(
        'SELECT * FROM public.rpc_qty_suggestion($1::uuid, $2)',
        [session_id, item_no]
      );
      
      if (result.rows.length === 0 || !result.rows[0].found) {
        return res.json({
          ok: true,
          found: false,
          expected_qty: null,
          remaining_qty: null
        });
      }
      
      await audit({
        actor: { username: req.user.username, role: req.user.role },
        event_type: 'QTY_SUGGESTED',
        entity_type: 'SESSION',
        entity_id: session_id,
        payload: { item_no, remaining_qty: result.rows[0].remaining_qty }
      });
      
      res.json({
        ok: true,
        found: true,
        expected_qty: parseFloat(result.rows[0].expected_qty),
        remaining_qty: parseFloat(result.rows[0].remaining_qty)
      });
    } catch (e) {
      console.error('qty-suggestion error:', e);
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // ----------------------------------------------------------------------------
  // 4) Operator GTIN Mapping
  // ----------------------------------------------------------------------------

  // POST /api/operator/map-gtin
  app.post('/api/operator/map-gtin', auth, requireRole('operator', 'admin'), async (req, res) => {
    try {
      const { gtin, item_no } = req.body;
      
      if (!gtin || !item_no) {
        return res.status(400).json({ ok: false, error: 'MISSING_GTIN_OR_ITEM' });
      }
      
      // Call RPC function
      const result = await q(
        'SELECT * FROM public.rpc_map_gtin_operator($1, $2, $3)',
        [gtin, item_no, req.user.username]
      );
      
      if (result.rows.length === 0) {
        return res.status(500).json({ ok: false, error: 'RPC_FAILED' });
      }
      
      const data = result.rows[0];
      
      if (!data.ok) {
        return res.status(400).json({ ok: false, error: data.error || 'MAPPING_FAILED' });
      }
      
      res.json({
        ok: true,
        gtin: data.gtin,
        item_no: data.item_no,
        item_name: data.item_name
      });
    } catch (e) {
      console.error('operator/map-gtin error:', e);
      
      // Handle specific errors from RPC
      if (e.message && e.message.includes('INVALID_GTIN')) {
        return res.status(400).json({ ok: false, error: 'INVALID_GTIN' });
      }
      if (e.message && e.message.includes('UNKNOWN_ITEM_NO')) {
        return res.status(400).json({ ok: false, error: 'UNKNOWN_ITEM_NO' });
      }
      if (e.message && e.message.includes('GTIN_ALREADY_MAPPED')) {
        return res.status(409).json({ ok: false, error: 'GTIN_ALREADY_MAPPED' });
      }
      
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // ----------------------------------------------------------------------------
  // 5) Transaction Log APIs
  // ----------------------------------------------------------------------------

  // POST /api/tx-log - Record transaction
  app.post('/api/tx-log', auth, requireRole('operator', 'admin'), async (req, res) => {
    try {
      const {
        tx_type,
        gtin,
        item_no,
        qty,
        lot,
        exp,
        raw_scan,
        session_id,
        status,
        expected_qty
      } = req.body;
      
      if (!tx_type || !gtin || !item_no || !qty || qty <= 0) {
        return res.status(400).json({ ok: false, error: 'MISSING_REQUIRED_FIELDS' });
      }
      
      const result = await q(
        `INSERT INTO public.tx_log 
         (created_by, tx_type, gtin, item_no, qty, lot, exp, raw_scan, session_id, status, expected_qty)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING *`,
        [
          req.user.username,
          tx_type,
          gtin,
          item_no,
          qty,
          lot || null,
          exp || null,
          raw_scan || null,
          session_id || null,
          status || 'COMPLETE',
          expected_qty || null
        ]
      );
      
      await audit({
        actor: { username: req.user.username, role: req.user.role },
        event_type: 'TX_RECORDED',
        entity_type: 'TX',
        entity_id: result.rows[0].id,
        payload: { tx_type, item_no, qty }
      });
      
      res.json({ ok: true, tx: result.rows[0] });
    } catch (e) {
      console.error('tx-log create error:', e);
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // GET /api/tx-log - Query transactions
  app.get('/api/tx-log', auth, requireRole('operator', 'admin'), async (req, res) => {
    try {
      const { item_no, gtin, session_id, status, from_date, limit } = req.query;
      const isAdmin = req.user.role === 'admin';
      
      let query = 'SELECT * FROM public.tx_log WHERE 1=1';
      const params = [];
      let paramCount = 0;
      
      // Non-admin users can only see their own transactions
      if (!isAdmin) {
        paramCount++;
        query += ` AND created_by = $${paramCount}`;
        params.push(req.user.username);
      }
      
      if (item_no) {
        paramCount++;
        query += ` AND item_no = $${paramCount}`;
        params.push(item_no);
      }
      
      if (gtin) {
        paramCount++;
        query += ` AND gtin = $${paramCount}`;
        params.push(gtin);
      }
      
      if (session_id) {
        paramCount++;
        query += ` AND session_id = $${paramCount}`;
        params.push(session_id);
      }
      
      if (status) {
        paramCount++;
        query += ` AND status = $${paramCount}`;
        params.push(status);
      }
      
      if (from_date) {
        paramCount++;
        query += ` AND created_at >= $${paramCount}`;
        params.push(from_date);
      }
      
      query += ' ORDER BY created_at DESC';
      
      const limitValue = parseInt(limit) || 100;
      paramCount++;
      query += ` LIMIT $${paramCount}`;
      params.push(limitValue);
      
      const result = await q(query, params);
      res.json({ ok: true, transactions: result.rows });
    } catch (e) {
      console.error('tx-log query error:', e);
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // GET /api/tx-log/stats - Get statistics (admin only)
  app.get('/api/tx-log/stats', auth, requireRole('admin'), async (req, res) => {
    try {
      const { from_date } = req.query;
      
      let query = `
        SELECT 
          COUNT(*) as total_count,
          COUNT(DISTINCT item_no) as unique_items,
          SUM(qty) as total_qty,
          status,
          tx_type
        FROM public.tx_log
        WHERE 1=1
      `;
      const params = [];
      
      if (from_date) {
        query += ' AND created_at >= $1';
        params.push(from_date);
      }
      
      query += ' GROUP BY status, tx_type';
      
      const result = await q(query, params);
      res.json({ ok: true, stats: result.rows });
    } catch (e) {
      console.error('tx-log stats error:', e);
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // ----------------------------------------------------------------------------
  // 6) Updated GTIN Map Endpoints
  // ----------------------------------------------------------------------------

  // PATCH /api/gtin-map/:gtin/deactivate - Deactivate mapping (admin)
  app.patch('/api/gtin-map/:gtin/deactivate', auth, requireRole('admin'), async (req, res) => {
    try {
      const { gtin } = req.params;
      const { reason } = req.body;
      
      const result = await q(
        `UPDATE public.gtin_map 
         SET active = false, 
             status = 'INACTIVE',
             deactivated_at = NOW(),
             deactivated_by = $1,
             deactivated_reason = $2
         WHERE gtin = $3 AND active = true
         RETURNING *`,
        [req.user.username, reason || null, gtin]
      );
      
      if (result.rows.length === 0) {
        return res.status(404).json({ ok: false, error: 'GTIN_NOT_FOUND_OR_ALREADY_INACTIVE' });
      }
      
      await audit({
        actor: { username: req.user.username, role: req.user.role },
        event_type: 'GTIN_DEACTIVATED',
        entity_type: 'GTIN',
        entity_id: gtin,
        payload: { reason }
      });
      
      res.json({ ok: true, mapping: result.rows[0] });
    } catch (e) {
      console.error('gtin-map deactivate error:', e);
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // GET /api/gtin-map/:gtin/history - View history (admin)
  app.get('/api/gtin-map/:gtin/history', auth, requireRole('admin'), async (req, res) => {
    try {
      const { gtin } = req.params;
      
      const result = await q(
        `SELECT * FROM public.gtin_map 
         WHERE gtin = $1 
         ORDER BY created_at DESC`,
        [gtin]
      );
      
      res.json({ ok: true, history: result.rows });
    } catch (e) {
      console.error('gtin-map history error:', e);
      res.status(500).json({ ok: false, error: 'INTERNAL_ERROR' });
    }
  });

  // ============================================================================
  // End of New APIs
  // ============================================================================


// ============================================================================
// Compatibility APIs for the static UI (No-Block friendly)
// These routes exist because some static UIs call /api/parse-validate and /api/commit.
// They do NOT require Idempotency-Key and they NEVER BLOCK; they return WARN with reasons.
// ============================================================================

function uiParsedFromSegments(segments, raw) {
  const ai = {};
  for (const s of (segments || [])) {
    if (s && s.ai && s.ai !== "??") ai[s.ai] = s.value;
  }
  const out = { ai, raw: String(raw || "") };

  // Common GS1 fields
  if (ai["00"]) out.sscc = ai["00"];
  if (ai["01"]) out.gtin = ai["01"];
  if (ai["02"]) out.content_gtin = ai["02"];
  if (ai["10"]) out.lot = ai["10"];
  if (ai["11"]) out.prod_date = ai["11"];
  if (ai["12"]) out.due_date = ai["12"];
  if (ai["13"]) out.pack_date = ai["13"];
  if (ai["15"]) out.best_before = ai["15"];
  if (ai["17"]) out.expiry = ai["17"];
  if (ai["21"]) out.serial = ai["21"];
  if (ai["30"] || ai["37"]) out.qty = ai["30"] || ai["37"];
  if (ai["240"]) out.additional_id = ai["240"];
  if (ai["241"]) out.customer_part = ai["241"];
  if (ai["400"]) out.order_no = ai["400"];
  if (ai["414"]) out.location_gln = ai["414"];

  // Non-GS1 payload helpers (QR / custom codes)
  if (ai["URI"]) out.uri = ai["URI"];
  if (ai["JSON"]) out.json = ai["JSON"];
  if (ai["HIBC"]) out.hibc = ai["HIBC"];
  if (ai["ID"]) out.id = ai["ID"];

  // Derived dates
  if (out.expiry && /^\d{6}$/.test(out.expiry)) {
    const pe = parseExpiryYYMMDD(out.expiry);
    if (!pe.error) out.expiry_iso = pe.iso;
  }
  if (out.best_before && /^\d{6}$/.test(out.best_before)) {
    const pe = parseExpiryYYMMDD(out.best_before);
    if (!pe.error) out.best_before_iso = pe.iso;
  }

  return out;
}

app.post("/api/parse-validate", auth, requireRole("operator", "admin", "auditor"), async (req, res) => {
  const raw = String(req.body?.raw ?? req.body?.raw_string ?? "").trim();
  const policy = await getActivePolicy();

  if (!raw) {
    return res.json({
      decision: "WARN",
      normalized: "",
      parsed: uiParsedFromSegments([], ""),
      parse_meta: { no_block: NO_BLOCK, empty: true },
      checks: [{ code: "EMPTY_INPUT", severity: "WARN", message: "Empty barcode payload." }],
      policy_applied: policy,
    });
  }

  const parsedBundle = parseBarcode(raw, policy, { template: "LEGACY_UI" });
  const d = decide(parsedBundle, policy);

  res.json({
    decision: d.decision,
    normalized: parsedBundle.normalized,
    parsed: uiParsedFromSegments(parsedBundle.segments, raw),
    parse_meta: d.meta,
    checks: d.checks,
    policy_applied: policy,
  });
});


// Compatibility endpoints used by the UI (parse / validate split)
app.post("/api/parse", auth, requireRole("operator", "admin", "auditor"), async (req, res) => {
  const raw = String(req.body?.raw ?? req.body?.raw_string ?? "").trim();
  const policy = await getActivePolicy();
  if (!raw) {
    return res.json({
      normalized: "",
      parsed: uiParsedFromSegments([], ""),
      parse_meta: { no_block: NO_BLOCK, empty: true },
      policy_applied: policy,
    });
  }
  const parsedBundle = parseBarcode(raw, policy, { template: "LEGACY_UI" });
  return res.json({
    normalized: parsedBundle.normalized,
    parsed: uiParsedFromSegments(parsedBundle.segments, raw),
    parse_meta: parsedBundle.meta || {},
    policy_applied: policy,
  });
});

app.post("/api/validate", auth, requireRole("operator", "admin", "auditor"), async (req, res) => {
  const raw = String(req.body?.raw ?? req.body?.raw_string ?? "").trim();
  const policy = await getActivePolicy();
  if (!raw) {
    return res.json({
      decision: "WARN",
      normalized: "",
      checks: [{ code: "EMPTY_INPUT", severity: "WARN", message: "Empty barcode payload." }],
      parse_meta: { no_block: NO_BLOCK, empty: true },
      policy_applied: policy,
    });
  }
  const parsedBundle = parseBarcode(raw, policy, { template: "LEGACY_UI" });
  const d = decide(parsedBundle, policy);
  return res.json({
    decision: d.decision,
    normalized: parsedBundle.normalized,
    checks: d.checks,
    parse_meta: d.meta,
    policy_applied: policy,
  });
});

// Some UI builds call this name
app.post("/api/scan/validate", auth, requireRole("operator", "admin", "auditor"), async (req, res) => {
  // Return the same contract as /api/parse-validate
  const raw = String(req.body?.raw ?? req.body?.raw_string ?? "").trim();
  req.body = { raw };
  return app._router.handle(req, res, () => {});
});


// Legacy commit for static UI: always succeeds (SIMULATED) and returns warnings.
app.post("/api/commit", auth, requireRole("operator", "admin", "auditor"), async (req, res) => {
  const raw = String(req.body?.raw ?? "").trim();
  const commitType = String(req.body?.commitType ?? "RECEIPT").toUpperCase();
  const template = String(req.body?.template ?? "UI").toUpperCase();

  const posting_intent =
    commitType === "TRANSFER" ? "TRANSFER_RECEIPT" : "PURCHASE_RECEIPT";

  // Create/Upsert a scan row (so dashboards/audit work)
  const scan_id = `UI-${Date.now()}-${String(Math.floor(Math.random() * 1e6)).padStart(6, "0")}`;
  const policy = await getActivePolicy();
  const parsedBundle = raw ? parseBarcode(raw, policy, { template, commitType, source: "ui_commit" }) : { normalized: "", segments: [], meta: {} };
  const normalized = parsedBundle.normalized || "";
  const d = decide(parsedBundle, policy);

  const scanRowId = `SCAN-${scan_id}`;
  const context = { source: "ui_commit", template, client_ts: req.body?.client_ts || nowIso(), commitType };

  await q(
    `
    INSERT INTO scans (id, scan_id, raw_string, normalized, decision, checks, parsed, context)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
    ON CONFLICT (id) DO UPDATE SET
      raw_string=EXCLUDED.raw_string,
      normalized=EXCLUDED.normalized,
      decision=EXCLUDED.decision,
      checks=EXCLUDED.checks,
      parsed=EXCLUDED.parsed,
      context=EXCLUDED.context
  `,
    [scanRowId, scan_id, raw, normalized, d.decision, d.checks, parsedBundle.segments, context]
  );

  // Simulated BC result (same format as /api/postings/commit)
  const simulatedDocNo = `SIM-${posting_intent === "PURCHASE_RECEIPT" ? "PR" : "TR"}-${new Date().getFullYear()}-${String(
    Math.floor(Math.random() * 1000000)
  ).padStart(6, "0")}`;

  const response = {
    ok: true,
    mode: BC_MODE,
    scan_id,
    posting_intent,
    warnings: d.checks,
    bc_result: {
      status: "SIMULATED_OK",
      document_no: simulatedDocNo,
    },
    correlation_id: uuid(),
    notes: "SIMULATED commit via /api/commit (UI compatibility).",
  };

  // Store posting (best effort)
  try {
    await q(
      `INSERT INTO bc_postings (id, scan_id, posting_intent, idempotency_key, request_hash, status, response, actor_username)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [uuid(), scan_id, posting_intent, null, hashPayload({ scan_id, posting_intent, template }), response.bc_result.status, response, req.user.username]
    );
  } catch (e) {
    // ignore
  }

  await audit({
    actor: { username: req.user.username, role: req.user.role },
    event_type: "UI_COMMIT",
    entity_type: "scan",
    entity_id: scanRowId,
    payload: { scan_id, posting_intent, decision: d.decision, checks_count: d.checks.length },
  });

  res.json(response);
});

// Offline queue consumer used by some static UIs
app.post("/api/queue/consume", auth, requireRole("operator", "admin", "auditor"), async (req, res) => {
  const job = req.body || {};
  if (job.type === "commit") {
    return res.json({ ok: true, note: "Use /api/commit directly (UI compatibility).", job });
  }
  return res.json({ ok: true, ignored: true });
});

// -------- Serve static frontend (same origin) --------
  const staticDir = path.join(__dirname, "public");
  if (fs.existsSync(staticDir)) {
    app.use("/", express.static(staticDir, { extensions: ["html"] }));
  }

  console.log('✅ New APIs loaded:');
  console.log('  - Items Cache: /api/items-cache, /api/items-cache/top200');
  console.log('  - Work Sessions: /api/work-sessions, /api/work-sessions/:id');
  console.log('  - Qty Suggestion: /api/qty-suggestion');
  console.log('  - Operator Mapping: /api/operator/map-gtin');
  console.log('  - Transaction Log: /api/tx-log');
  console.log('  - GTIN Map Updates: deactivate, history');

  return app;
}

export async function startServer() {
  await ensureSchema();
  await seed();

  const app = createApp();
  app.listen(PORT, () => {
    console.log(`GS1/UDI Supabase-Ready App listening on :${PORT}`);
  });
}

// ---- IMPORTANT: no auto-start on import ----
if (process.argv[1] === __filename) {
  startServer().catch((e) => {
    console.error("Startup failed:", e);
    process.exit(1);
  });
}
