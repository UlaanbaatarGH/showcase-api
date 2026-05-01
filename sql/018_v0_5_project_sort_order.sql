-- V2 / FIX400.2.1.1 + FIX351.2.7 / .2.8: project ordering.
-- Add a sort_order column on project so the admin Projects panel can
-- move rows up / down and the home page lists them in the same order.
-- Idempotent: safe to re-run.


alter table project
  add column if not exists sort_order integer not null default 0;

-- Backfill: spread existing rows in id order, gap of 10 between
-- successive entries so future inserts can slip in without cascading
-- updates.
update project p
   set sort_order = ranked.rn * 10
  from (
    select id, row_number() over (order by id) as rn
      from project
  ) as ranked
 where p.id = ranked.id
   and p.sort_order = 0;

create index if not exists project_sort_order_idx on project(sort_order, id);
