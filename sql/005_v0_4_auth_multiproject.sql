-- Showcase V0.4: auth, multi-project, Master Folders
-- Covers FIX300 (Access Rights), FIX310 (User), FIX350 (Project + Master Folder tree).
-- Idempotent: safe to re-run.


-- ============================================================
-- FIX310: User
-- ============================================================
-- app_user.id matches the Supabase auth.users uuid.
-- Password is held by Supabase Auth, not here.
create table if not exists app_user (
  id         uuid primary key,
  login_name text not null unique,
  profile    text not null default 'common',
  created_at timestamptz not null default now(),
  constraint app_user_profile_check check (profile in ('admin', 'common'))
);


-- ============================================================
-- FIX350.1: Project — extend existing table
-- ============================================================
alter table project
  add column if not exists cover_image_key text,
  add column if not exists root_directory  text,
  add column if not exists is_public       boolean not null default false,
  add column if not exists owner_id        uuid references app_user(id) on delete set null;


-- ============================================================
-- FIX310.1.4 + FIX300: per-user per-project access rights
-- ============================================================
-- Rights stored as a subset of 'CRUD' letters (e.g. '', 'R', 'CRU', 'CRUD').
-- group2 maps to FIX350.10.1.2 actions, group3 to FIX350.10.1.3 actions.
create table if not exists project_access (
  user_id       uuid not null references app_user(id) on delete cascade,
  project_id    bigint not null references project(id) on delete cascade,
  group2_rights text not null default '',
  group3_rights text not null default '',
  created_at    timestamptz not null default now(),
  primary key (user_id, project_id),
  constraint project_access_group2_chars check (group2_rights ~ '^[CRUD]*$'),
  constraint project_access_group3_chars check (group3_rights ~ '^[CRUD]*$')
);


-- ============================================================
-- FIX350.2.1: folder tree (parent_id) + FIX350.2.3: Master Folder flag
-- ============================================================
-- parent_id NULL = root folder of a project (exactly one per project).
-- is_master = this folder defines the list of property names
-- for itself and all its descendants (FIX350.2.3.1).
alter table folder
  add column if not exists parent_id bigint references folder(id) on delete cascade,
  add column if not exists is_master boolean not null default false;

create index if not exists folder_parent_idx
  on folder(parent_id, sort_order);

-- Backfill: every project must have a root folder; that root is the Master Folder.
-- If the project has no root yet, create one named after the project and re-parent
-- all existing flat folders to it.
do $$
declare
  p record;
  new_root_id bigint;
begin
  for p in select id, name from project loop
    if exists (select 1 from folder where project_id = p.id and parent_id is null) then
      -- Root already exists. Promote it to Master if nothing else is Master yet.
      if not exists (select 1 from folder where project_id = p.id and is_master) then
        update folder
           set is_master = true
         where id = (
           select id from folder
            where project_id = p.id and parent_id is null
            order by sort_order, id
            limit 1
         );
      end if;
    else
      insert into folder (project_id, name, sort_order, is_master)
      values (p.id, p.name, 0, true)
      returning id into new_root_id;

      update folder
         set parent_id = new_root_id
       where project_id = p.id and id <> new_root_id and parent_id is null;
    end if;
  end loop;
end$$;


-- ============================================================
-- FIX350.2.3.1: property list is defined per Master Folder, not per project
-- ============================================================
alter table property
  add column if not exists master_folder_id bigint references folder(id) on delete cascade;

-- One-shot migration: copy project_id -> master_folder_id, then drop project_id.
do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_name = 'property' and column_name = 'project_id'
  ) then
    update property pr
       set master_folder_id = f.id
      from folder f
     where pr.master_folder_id is null
       and f.project_id = pr.project_id
       and f.is_master;

    alter table property alter column master_folder_id set not null;
    drop index if exists property_project_idx;
    alter table property drop column project_id;
  end if;
end$$;

create index if not exists property_master_folder_idx
  on property(master_folder_id, sort_order);
