-- Showcase V0.5: introduce the 'visitor' app_user profile.
-- Covers FIX316.2.1 (New Visitor Access self-signup) — visitors are
-- the lambda-user role that browses the catalogue and can keep a
-- private wishlist, but cannot edit any data.
-- Idempotent: safe to re-run.

alter table app_user
  drop constraint if exists app_user_profile_check;

alter table app_user
  add constraint app_user_profile_check
  check (profile in ('admin', 'common', 'visitor'));
