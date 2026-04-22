-- Ops: keep the Render free-tier API awake by pinging /api/health every 5 min.
-- Render sleeps after ~15 min idle; a cold start takes 25-50s and shows a
-- frozen "Loading…" to visitors. GitHub Actions cron was unreliable (runs
-- were 2-6h apart in practice), so we drive the ping from Supabase itself
-- via pg_cron + pg_net.
--
-- Run once in the Supabase SQL editor. Idempotent — safe to re-run.

create extension if not exists pg_cron;
create extension if not exists pg_net;

-- Unschedule any prior version of this job before re-scheduling.
do $$
begin
  if exists (select 1 from cron.job where jobname = 'showcase-api-keep-alive') then
    perform cron.unschedule('showcase-api-keep-alive');
  end if;
end $$;

select cron.schedule(
  'showcase-api-keep-alive',
  '*/5 * * * *',
  $$ select net.http_get('https://showcase-api-muxl.onrender.com/api/health') $$
);

-- Verify: should show one row for 'showcase-api-keep-alive'.
-- select jobname, schedule, active from cron.job;
--
-- Inspect recent ping results (most recent first):
-- select id, status_code, created
--   from net._http_response
--   order by id desc
--   limit 10;
