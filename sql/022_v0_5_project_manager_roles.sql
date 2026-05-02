-- Showcase V0.5: split project_access "manager" role into two
-- Covers FIX351.2.1.2 (Column 'Data Managers') + FIX351.2.1.5
-- (Column 'User Managers') + FIX312.5.2 (only User Managers can
-- grant project access to users).
-- Idempotent: safe to re-run.

alter table project_access
  add column if not exists is_data_manager boolean not null default true,
  add column if not exists is_user_manager boolean not null default false;

-- Backfill: every project_access row that pre-dated this migration
-- represented "full manager" semantics (the old single role). Promote
-- those rows to both roles so existing managers don't lose their
-- ability to grant access to other users. Going forward the column
-- default (is_user_manager=false) keeps the new privileged role
-- opt-in — only admins can flip it on via <panel-project>
-- (FIX352.3.10.11).
update project_access set is_user_manager = true where is_user_manager = false;
