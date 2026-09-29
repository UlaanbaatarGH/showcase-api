-- Enable RLS on the V0.6 rating tables (036/037), flagged by the
-- Supabase linter (rls_disabled_in_public). No policies: the frontend
-- never reads tables via PostgREST (supabase-js is auth-only); main.py
-- connects directly as the table owner, which bypasses RLS. Net effect:
-- anon/authenticated API access is denied, backend unaffected.
-- Idempotent: safe to re-run.

alter table rating_value  enable row level security;
alter table project_rater enable row level security;
alter table item_rating   enable row level security;
