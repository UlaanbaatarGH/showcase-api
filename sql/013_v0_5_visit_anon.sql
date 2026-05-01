-- Showcase V0.5: anonymous-aware visit log
-- Updates FIX410.1.1.1.1 — track every consultation of the App home
-- page and the Project home page, regardless of sign-in status.
-- Idempotent: safe to re-run.


-- Allow visits without a signed-in user.
alter table visit
  alter column user_id drop not null;

-- Distinguish *who* (when known) from *where* and *from where*.
alter table visit
  add column if not exists ip   text,
  add column if not exists page text;

create index if not exists visit_ip_page_ts_idx on visit(ip, page, ts desc);
