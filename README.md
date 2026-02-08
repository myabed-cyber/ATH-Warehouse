# GS1/UDI Enterprise Hub (Clean Deploy)

## What this repo includes
- Node.js (Express) API + static UI (served from `/public`)
- Supabase Postgres schema (`/database/bootstrap.sql`)
- Dockerfile for Northflank

## Required environment variables (Northflank Secrets)
- DATABASE_URL
- JWT_SECRET_EFFECTIVE
- SEED_ADMIN_PASS
- SEED_OPERATOR_PASS
- AUTO_SCHEMA=true (recommended for first deploy)
- CORS_ORIGINS (optional; comma-separated)

- PGSSL_VERIFY (optional): set `true` to enforce certificate validation
- PGSSL (optional): set `false` to disable TLS (not recommended)

## Quick local run
1) Copy `.env.example` → `.env` and fill values
2) `npm install`
3) `npm start`


## Seed users (bootstrap)

This project can bootstrap an **admin** and an **operator** user on startup.

**Env vars**
- `SEED_ADMIN_USER`, `SEED_ADMIN_PASS`
- `SEED_OPERATOR_USER`, `SEED_OPERATOR_PASS`
- `SEED_MODE`:
  - `off`    → do nothing
  - `once`   → seed only the *first time* (tracked in `seed_meta`)
  - `upsert` → re-apply seed if values change (safe, repeatable)
  - `reset`  → delete all rows in `users` then insert seed users (destructive)
- `SEED_VERSION` (optional): bump to force a re-seed in `upsert/reset` modes
- `SEED_FORCE` (optional): set `true` to force re-seed on next boot
- `SEED_STRICT_BOOTSTRAP` (optional): if `true`, the app will refuse to start until seed vars are set

**Recommended production flow**
1) Set `SEED_MODE=upsert` for the first deploy (or when you need to reset the seed users).
2) After first login and creating real users via the admin API/UI, set `SEED_MODE=off`.

> Important: No insecure hard-coded default credentials exist. If you don't provide seed env vars and the users table is empty, the app will refuse to start when `SEED_STRICT_BOOTSTRAP=true`.

## DATABASE_URL special characters

If your `DATABASE_URL` password contains special characters (e.g. `@`), you must URL-encode them inside the connection string:
- `@` → `%40`

Example:
`postgresql://user:Veron%40a2579@host:6543/postgres`
