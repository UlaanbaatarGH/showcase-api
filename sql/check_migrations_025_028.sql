-- Verify migrations 025–028 have been applied on Supabase.
-- Paste the whole file into the Supabase SQL editor and run.
-- Returns one row per fingerprint: applied = true means that piece
-- is already in place. Anything false = re-run the matching
-- migration file (all of them are idempotent — safe to re-run).

select '025 app_setting table'              as migration,
       to_regclass('app_setting') is not null as applied
union all
select '025 contact_to seed',
       exists (select 1 from app_setting where key = 'contact_to')
union all
select '026 contact_message.echo_message_id',
       exists (select 1 from information_schema.columns
               where table_name = 'contact_message'
                 and column_name = 'echo_message_id')
union all
select '026 contact_message.email_invalid',
       exists (select 1 from information_schema.columns
               where table_name = 'contact_message'
                 and column_name = 'email_invalid')
union all
select '027 contact_message.project_id',
       exists (select 1 from information_schema.columns
               where table_name = 'contact_message'
                 and column_name = 'project_id')
union all
select '028 project.front_introduction',
       exists (select 1 from information_schema.columns
               where table_name = 'project'
                 and column_name = 'front_introduction')
union all
select '028 project.introduction',
       exists (select 1 from information_schema.columns
               where table_name = 'project'
                 and column_name = 'introduction')
union all
select '028 project_slug table',
       to_regclass('project_slug') is not null
union all
select '028 project_slug active-label unique idx',
       exists (select 1 from pg_indexes
               where indexname = 'project_slug_label_active_uidx')
union all
select '028 project_slug one-official-per-project idx',
       exists (select 1 from pg_indexes
               where indexname = 'project_slug_one_official_uidx')
union all
select '028 project_slug backfilled (>=1 row per project)',
       not exists (
         select 1 from project p
         where not exists (select 1 from project_slug s where s.project_id = p.id)
       );
