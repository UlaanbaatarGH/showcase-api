-- Showcase V0.5: contact-admin messages
-- Covers FIX420.3 — anonymous Contact panel posts land here. The
-- backend rate-limits sends to once-per-minute per IP via this
-- table (FIX420.4.1).
-- Idempotent: safe to re-run.

create table if not exists contact_message (
  id           bigserial primary key,
  ip           text,
  subject      text not null,
  body         text not null,
  sender_email text not null,
  ts           timestamptz not null default now()
);

create index if not exists contact_message_ip_ts_idx
  on contact_message(ip, ts desc);
