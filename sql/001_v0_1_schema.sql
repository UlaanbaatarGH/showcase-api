-- Showcase V0.1 schema
-- Apply in the Supabase SQL editor. Idempotent: safe to re-run.

create table if not exists project (
  id         bigserial primary key,
  name       text not null,
  created_at timestamptz not null default now()
);

create table if not exists folder (
  id         bigserial primary key,
  project_id bigint not null references project(id) on delete cascade,
  name       text not null,
  note       text,
  sort_order integer not null default 0,
  created_at timestamptz not null default now()
);

create index if not exists folder_project_idx
  on folder(project_id, sort_order);

create table if not exists image (
  id          bigserial primary key,
  storage_key text not null unique,
  rotation    integer not null default 0,
  created_at  timestamptz not null default now()
);

create table if not exists folder_image (
  id         bigserial primary key,
  folder_id  bigint not null references folder(id) on delete cascade,
  image_id   bigint not null references image(id) on delete restrict,
  caption    text,
  is_main    boolean not null default false,
  sort_order integer not null default 0,
  created_at timestamptz not null default now()
);

create index if not exists folder_image_folder_idx
  on folder_image(folder_id, sort_order);

-- At most one main image per folder
create unique index if not exists folder_image_one_main_per_folder
  on folder_image(folder_id) where is_main;
