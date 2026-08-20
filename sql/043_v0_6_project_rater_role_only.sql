-- FIX507.2.3(removed): <table-users-allowed-to-rate> (acronym +
-- enabled, admin-editable) is replaced by <role-rater>
-- (project_access.is_rater, migration 042). project_rater becomes a
-- plain (project_id, user_id) mirror of is_rater, kept only so
-- existing view_setup grouping columns ({"type":"user_rating",
-- "rater_id": N}) keep resolving to a stable id. Idempotent.

delete from project_rater pr
where not exists (
  select 1 from project_access pa
  where pa.project_id = pr.project_id
    and pa.user_id = pr.user_id
    and pa.is_rater
);

alter table project_rater drop column if exists acronym;
alter table project_rater drop column if exists enabled;
