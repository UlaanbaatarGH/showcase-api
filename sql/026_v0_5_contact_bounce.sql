-- Showcase V0.5: track bounce status of the echo email
-- The /api/webhooks/resend endpoint flips email_invalid=true on
-- contact_message rows whose echo bounced or was reported as spam,
-- so the admin can tell at a glance which messages aren't worth
-- replying to. Idempotent.

alter table contact_message
  add column if not exists echo_message_id text,
  add column if not exists email_invalid   boolean not null default false;

create index if not exists contact_message_echo_msg_idx
  on contact_message(echo_message_id)
  where echo_message_id is not null;
