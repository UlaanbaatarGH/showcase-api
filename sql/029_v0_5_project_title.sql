-- Showcase V0.5: project page title (FIX352.2.7 + FIX503.2.13).
-- Optional decorative label rendered in the project header next to
-- the About button. Independent of the project name; admins use it
-- to add context like a tagline.
-- Idempotent: safe to re-run.

alter table project
  add column if not exists title_text    text    not null default '',
  add column if not exists title_size    integer,
  add column if not exists title_colour  text,
  add column if not exists title_is_bold boolean not null default false;
