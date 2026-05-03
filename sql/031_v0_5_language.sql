-- Showcase V0.5: language / i18n storage (FIX509).
-- One row per language (code = ISO 639-1 like 'en' / 'fr', or any
-- short tag the admin chooses). `labels` is the per-language map
-- from i18n keys (defined in src/i18n/keys.js) to translated text;
-- missing keys fall back to the default language, then to the
-- hardcoded English default in the code registry.
-- Idempotent: safe to re-run.

create table if not exists language (
    code        text primary key,
    name        text not null,
    is_default  boolean not null default false,
    labels      jsonb not null default '{}'::jsonb,
    sort_order  integer not null default 0
);

-- Exactly one language can be marked default at a time
-- (FIX509 functional rule: missing keys resolve via the default).
create unique index if not exists language_one_default_uidx
    on language(is_default) where is_default;

-- Seed: English as the initial default. Re-running the migration
-- never disturbs an admin who later rewrote the seed (on conflict
-- skips the row).
insert into language (code, name, is_default, sort_order)
values ('en', 'English', true, 0)
on conflict (code) do nothing;
