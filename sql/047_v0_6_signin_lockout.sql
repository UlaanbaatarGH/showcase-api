-- Showcase V0.6 / FIX310.12 + FIX405.4: per-user sign-in lockout.
-- failed_signin_attempts counts consecutive failed sign-ins since the
-- last success. is_locked_out (FIX310.12 <user-is-locked-out>) flips
-- true once that count reaches <sign-in-possible-attempts> (FIX405.4.2
-- = 3). FIX405.4.1.2 tells a locked-out user to get a fresh access
-- code from their administrator, so the only place both are cleared
-- is the existing <process-reset-pswd> (FIX318).
-- Idempotent: safe to re-run.

alter table app_user
  add column if not exists failed_signin_attempts integer not null default 0,
  add column if not exists is_locked_out boolean not null default false;
