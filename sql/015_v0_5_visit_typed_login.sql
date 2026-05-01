-- Showcase V0.5: typed login name on visit
-- Covers updated FIX412.5.1.1 — the User column shows the name the
-- user typed at sign-in, regardless of whether it matches a known
-- user or whether the attempt succeeded.
-- Idempotent: safe to re-run.


alter table visit
  add column if not exists typed_login text;
