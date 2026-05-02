-- Showcase V0.5: tag contact_message with the project the form was
-- submitted from. Powers the Project column in <panel-message-list>
-- (FIX421.2.1.2) and the per-project filter when the panel is
-- opened from a project's Admin menu (FIX421.1).
-- Idempotent.

alter table contact_message
  add column if not exists project_id bigint
  references project(id) on delete set null;

create index if not exists contact_message_project_ts_idx
  on contact_message(project_id, ts desc);
