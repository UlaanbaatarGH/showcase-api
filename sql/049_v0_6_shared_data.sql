-- Showcase V0.6: FIX415 <panel-shared-data> storage.
-- FIX415.1: a list of properties, each with a list of values.
-- Property names are unique (case-insensitive); within a property,
-- values are unique (case-insensitive). Global (not per project),
-- admin-managed via main.py. RLS on, no policies (see 048).
-- Idempotent: safe to re-run.

create table if not exists shared_property (
    id          bigserial primary key,
    name        text not null,
    sort_order  integer not null default 0
);
create unique index if not exists shared_property_name_uidx
    on shared_property (lower(name));

create table if not exists shared_property_value (
    id           bigserial primary key,
    property_id  bigint not null references shared_property(id) on delete cascade,
    value        text not null,
    sort_order   integer not null default 0
);
create unique index if not exists shared_property_value_uidx
    on shared_property_value (property_id, lower(value));

alter table shared_property       enable row level security;
alter table shared_property_value enable row level security;
