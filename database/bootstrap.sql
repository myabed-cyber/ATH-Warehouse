-- GS1/UDI Enterprise Hub - Supabase Bootstrap Schema
-- Apply this once in Supabase SQL Editor.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY,
  username text UNIQUE NOT NULL,
  password_hash text NOT NULL,
  role text NOT NULL CHECK(role IN ('operator','admin','auditor')),
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Tracks when seed values were applied (for idempotent seeding)
CREATE TABLE IF NOT EXISTS seed_meta (
  id int PRIMARY KEY DEFAULT 1,
  seed_version text NOT NULL,
  seed_hash text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
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
-- Items Cache: barcode mapping (primary + alternate) for non-GS1 IDs (Code128/Code39/HIBC/ISBT/etc.)
ALTER TABLE public.items_cache ADD COLUMN IF NOT EXISTS primary_barcode text;
ALTER TABLE public.items_cache ADD COLUMN IF NOT EXISTS barcode_type text;
ALTER TABLE public.items_cache ADD COLUMN IF NOT EXISTS alt_barcodes text[] NOT NULL DEFAULT ARRAY[]::text[];
CREATE INDEX IF NOT EXISTS idx_items_cache_primary_barcode ON public.items_cache(primary_barcode);
CREATE INDEX IF NOT EXISTS idx_items_cache_alt_barcodes_gin ON public.items_cache USING gin (alt_barcodes);

CREATE INDEX IF NOT EXISTS idx_work_sessions_status ON public.work_sessions(status);
CREATE INDEX IF NOT EXISTS idx_work_lines_session ON public.work_lines(session_id);
CREATE INDEX IF NOT EXISTS idx_tx_log_created_at ON public.tx_log(created_at);

-- -------- RPC helpers used by operator endpoints --------
CREATE OR REPLACE FUNCTION public.rpc_qty_suggestion(p_session_id uuid, p_item_no text)
RETURNS TABLE(found boolean, expected_qty numeric, scanned_qty numeric, remaining_qty numeric)
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public
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
SET search_path = pg_catalog, public
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
-- -------- Security hardening (Supabase Security Advisor) --------
-- Enable RLS on public tables exposed to PostgREST; deny anon/authenticated; allow service_role.
-- Note: Table owners (e.g., postgres) bypass RLS by default unless FORCE ROW LEVEL SECURITY is set (we do NOT force).

DO $$
DECLARE tbl text;
BEGIN
  FOREACH tbl IN ARRAY ARRAY[
    'seed_meta',
    'gtin_map',
    'audit_events',
    'items_cache',
    'bc_postings',
    'work_sessions',
    'work_lines',
    'tx_log',
    'policies',
    'scans',
    'users',
    'cases',
    'idempotency'
  ]
  LOOP
    IF to_regclass('public.' || tbl) IS NOT NULL THEN
      EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY;', tbl);

      -- Drop old policies if they exist (idempotent)
      EXECUTE format('DROP POLICY IF EXISTS deny_anon_and_authenticated ON public.%I;', tbl);
      EXECUTE format('DROP POLICY IF EXISTS allow_service_role_only ON public.%I;', tbl);

      -- Deny reads/writes to anon + authenticated
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon')
         AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE format(
          'CREATE POLICY deny_anon_and_authenticated ON public.%I FOR ALL TO anon, authenticated USING (false) WITH CHECK (false);',
          tbl
        );
      ELSE
        -- Fallback (very restrictive) if roles not found
        EXECUTE format(
          'CREATE POLICY deny_anon_and_authenticated ON public.%I FOR ALL TO public USING (false) WITH CHECK (false);',
          tbl
        );
      END IF;

      -- Allow service_role (Supabase server-side) if exists
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
        EXECUTE format(
          'CREATE POLICY allow_service_role_only ON public.%I FOR ALL TO service_role USING (true) WITH CHECK (true);',
          tbl
        );
      END IF;
    END IF;
  END LOOP;
END $$;

