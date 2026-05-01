-- Showcase V0.5: visit log
-- Covers FIX410.1.1.1.1 (Visits panel listing).
-- Idempotent: safe to re-run.


create table if not exists visit (
  id      bigserial primary key,
  user_id uuid not null references app_user(id) on delete cascade,
  ts      timestamptz not null default now()
);

create index if not exists visit_ts_idx on visit(ts desc);
create index if not exists visit_user_ts_idx on visit(user_id, ts desc);


-- Backfill: one row per existing user so the panel isn't empty after the
-- initial deploy. Subsequent visits accumulate via POST /api/users/me.
insert into visit (user_id, ts)
select id, now() from app_user
where not exists (select 1 from visit where visit.user_id = app_user.id);
