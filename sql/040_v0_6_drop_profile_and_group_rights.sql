-- Showcase V0.6: drop app_user.profile (superseded by is_admin, see
-- migration 039) and project_access.group2_rights/group3_rights
-- (the FIX350.10.1.2 / FIX350.10.1.3 access-rights groups -- never
-- enforced anywhere; every row was hardcoded 'CRUD'). Idempotent:
-- safe to re-run.

alter table app_user drop constraint if exists app_user_profile_check;
alter table app_user drop column if exists profile;

alter table project_access drop constraint if exists project_access_group2_chars;
alter table project_access drop constraint if exists project_access_group3_chars;
alter table project_access drop column if exists group2_rights;
alter table project_access drop column if exists group3_rights;
