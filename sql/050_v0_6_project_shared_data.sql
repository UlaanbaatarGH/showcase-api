-- Showcase V0.6: FIX352.2.14 <project-shared-data> storage.
-- The shared data (FIX415) a project uses. Only shared properties
-- exist so far, so kind is always 'property'. Removing a shared
-- property from <panel-shared-data> drops it from every project.
-- RLS on, no policies (see 048). Idempotent: safe to re-run.

create table if not exists project_shared_data (
    project_id   bigint  not null references project(id) on delete cascade,
    kind         text    not null default 'property' check (kind in ('property')),
    property_id  bigint  not null references shared_property(id) on delete cascade,
    sort_order   integer not null default 0,
    primary key (project_id, property_id)
);

alter table project_shared_data enable row level security;
