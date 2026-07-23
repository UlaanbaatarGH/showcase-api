-- FIX610.3.20: Website/Local app concurrent access.
-- Apply in the Supabase SQL editor. Idempotent: safe to re-run.
--
-- One lock row per project. holder ('local' | 'website') + session_token
-- identify who currently has <panel-showcase-img-list-editor> open;
-- last_heartbeat_at lets a stale lease (crashed/closed tab) be treated as
-- released without an explicit unlock (see EDIT_LOCK_TTL_SECONDS in main.py).
-- local_pending_changes is independent of the open/close lock above — true
-- whenever the local app has any staged (non-blank status) image change
-- not yet published, even if its editor isn't currently open.

create table if not exists project_edit_lock (
  project_id            bigint primary key references project(id) on delete cascade,
  holder                text,
  session_token         text,
  last_heartbeat_at      timestamptz,
  local_pending_changes  boolean not null default false
);
