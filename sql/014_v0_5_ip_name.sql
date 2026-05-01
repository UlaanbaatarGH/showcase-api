-- Showcase V0.5: per-IP friendly name
-- Covers FIX413 — Panel IP Address and stats.
-- Idempotent: safe to re-run.


create table if not exists ip_name (
  ip   text primary key,
  name text not null
);
