-- Showcase V0.2: folder properties
-- Idempotent: safe to re-run.

create table if not exists property (
  id         bigserial primary key,
  project_id bigint not null references project(id) on delete cascade,
  label      text not null,
  sort_order integer not null default 0,
  created_at timestamptz not null default now()
);

create index if not exists property_project_idx
  on property(project_id, sort_order);

alter table folder
  add column if not exists properties jsonb not null default '{}'::jsonb;

-- Seed 3 default properties for the 'Old books' project (idempotent via NOT EXISTS).
insert into property (project_id, label, sort_order)
select p.id, v.label, v.sort_order
from project p
cross join (values ('Year', 1), ('Author', 2), ('Pages', 3)) as v(label, sort_order)
where p.name = 'Old books'
  and not exists (
    select 1 from property x
    where x.project_id = p.id and x.label = v.label
  );
