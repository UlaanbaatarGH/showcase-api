-- FIX300: the 5 remaining role flags (role-data-mngr / role-user-mngr
-- already exist as is_data_manager / is_user_manager). is_viewer
-- defaults true: FIX300.3.10.1.1 -- Viewer is the default role
-- granted when a user is assigned to a project. Idempotent.

alter table project_access
  add column if not exists is_viewer boolean not null default true,
  add column if not exists is_rater boolean not null default false,
  add column if not exists is_layout_mngr boolean not null default false,
  add column if not exists is_setup_mngr boolean not null default false;

-- Backfill is_rater from the (about to be retired) project_rater.enabled,
-- creating a project_access row for anyone who has one without ever
-- having had one before.
insert into project_access (user_id, project_id, is_rater)
select pr.user_id, pr.project_id, true
from project_rater pr
where pr.enabled
on conflict (user_id, project_id) do update set is_rater = true;
