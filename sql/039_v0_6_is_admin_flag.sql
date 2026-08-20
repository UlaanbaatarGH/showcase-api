-- Showcase V0.6: replace the profile-string admin check with a proper
-- boolean flag. Idempotent: safe to re-run.

alter table app_user add column if not exists is_admin boolean not null default false;

update app_user set is_admin = true where profile = 'admin';
