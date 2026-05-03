-- Showcase V0.5: introduction texts on project + dedicated slug list.
-- Covers FIX352.2.5 (<project-front-introduction>),
-- FIX352.2.6 (<project-introduction>),
-- FIX352.2.10 + FIX352.3.{2,3,4} (<project-slugs> editable list).
-- Idempotent: safe to re-run.

-- 1) Free-form introductions on the project itself.
alter table project
  add column if not exists front_introduction text not null default '',
  add column if not exists introduction       text not null default '';

-- 2) project_slug: one row per slug. Multiple slugs per project keep
--    older URLs working after a rename (FIX352.3.4); exactly one is
--    the "official" slug — that's the one HomeView links to.
create table if not exists project_slug (
    id           bigserial primary key,
    project_id   bigint  not null references project(id) on delete cascade,
    label        text    not null,
    is_official  boolean not null default false,
    is_active    boolean not null default true,
    sort_order   integer not null default 0
);

-- Slug labels must be globally unique (URLs are global). Use a partial
-- unique index so only active slugs collide — inactive ones can be
-- kept as historical breadcrumbs without blocking re-use.
create unique index if not exists project_slug_label_active_uidx
    on project_slug(label) where is_active;

-- Exactly one official slug per project (FIX352.3.4.1). Enforced by
-- partial unique index over (project_id) where is_official.
create unique index if not exists project_slug_one_official_uidx
    on project_slug(project_id) where is_official;

-- 3) Helper: unaccent the input if the unaccent extension is present,
--    otherwise return it untouched. Keeps the migration runnable on
--    Postgres instances without `unaccent` installed.
create or replace function unaccent_if_available(t text) returns text
language plpgsql immutable as $$
declare
    has_ext boolean;
    out_text text;
begin
    select exists(select 1 from pg_extension where extname = 'unaccent')
      into has_ext;
    if has_ext then
        execute 'select unaccent($1)' into out_text using t;
        return out_text;
    end if;
    return t;
end;
$$;

-- 4) Backfill: every pre-existing project gets one row reflecting the
--    slug the SPA already derives from its name. Mirrors _slugify_name
--    in main.py (NFD-strip + lowercase + drop non-[a-z0-9]) so URLs
--    the public has been using keep resolving.
insert into project_slug (project_id, label, is_official, is_active, sort_order)
select
    p.id,
    regexp_replace(
        lower(unaccent_if_available(p.name)),
        '[^a-z0-9]+',
        '',
        'g'
    ) as label,
    true  as is_official,
    true  as is_active,
    0     as sort_order
from project p
where not exists (
    select 1 from project_slug s where s.project_id = p.id
);
