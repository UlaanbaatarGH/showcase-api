-- FIX312.4.3: adding a user to a project grants them exactly one role,
-- <role-viewer> -- is_data_manager must NOT come along for free. Migration
-- 022 (V0.5, pre-FIX300) set is_data_manager's default to true back when a
-- bare project_access row inherently meant "manager"; migration 042 fixed
-- is_viewer/is_rater/is_layout_mngr/is_setup_mngr's defaults for the new
-- 6-role model but missed this pre-existing column, so grant_user_project's
-- plain insert (only role-viewer's default relied on) was silently also
-- granting Data Manager to every newly added user.
-- Existing rows are untouched -- this only changes what a future insert
-- defaults to. Idempotent: safe to re-run.

alter table project_access
  alter column is_data_manager set default false;
