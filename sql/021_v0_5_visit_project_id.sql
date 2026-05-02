-- Showcase V0.5: tag 'project' visits with the project id
-- Covers updated FIX412.2.1.1.1 — the Page column on the Visits
-- history shows '{project-name}' instead of the generic 'Project'
-- tag, so the admin can tell which project was consulted.
-- Idempotent: safe to re-run.

alter table visit
  add column if not exists project_id bigint
  references project(id) on delete set null;

create index if not exists visit_project_ts_idx on visit(project_id, ts desc);
