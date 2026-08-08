-- FIX507.2.4 / FIX507.2.5: project-level rating-conflict settings.
-- Idempotent: safe to re-run.

alter table project
  add column if not exists show_rating_conflict boolean not null default false,
  add column if not exists rating_conflict_threshold integer not null default 2;
