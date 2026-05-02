-- Showcase V0.5: case-insensitive uniqueness on app_user.login_name.
-- The stored value preserves the user's preferred case (FIX310.1.1),
-- but lookups and uniqueness must be case-insensitive so that 'Herve'
-- and 'herve' resolve to the same handle.
--
-- Idempotent: re-running is a no-op once the index is in place.

alter table app_user
  drop constraint if exists app_user_login_name_key;

create unique index if not exists app_user_login_name_ci_key
  on app_user (lower(login_name));
