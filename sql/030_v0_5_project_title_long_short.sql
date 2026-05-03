-- Showcase V0.5: split project title into long / short variants.
-- Covers FIX352.2.7.1 (updated) + FIX352.2.7.4 + FIX503.5.4.
-- The header picks one of the two at render time based on viewport
-- width: long on PC, short on smartphone.
-- Idempotent: safe to re-run.

-- Step 1: rename the existing title_text column (preserves data)
-- to title_long_text. Wrapped in a DO block so a re-run after a
-- successful first execution is a no-op.
do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public'
      and table_name = 'project'
      and column_name = 'title_text'
  ) and not exists (
    select 1 from information_schema.columns
    where table_schema = 'public'
      and table_name = 'project'
      and column_name = 'title_long_text'
  ) then
    alter table project rename column title_text to title_long_text;
  end if;
end $$;

-- Step 2: add the new short variant + a safety-net for the long one
-- (covers projects created on a freshly bootstrapped DB that never
-- had migration 029 — both columns get created with sensible defaults).
alter table project
  add column if not exists title_long_text  text not null default '',
  add column if not exists title_short_text text not null default '';
