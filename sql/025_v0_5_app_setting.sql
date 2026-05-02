-- Showcase V0.5: app-wide settings table
-- Currently used for FIX420.3.1.3 — stores the recipient email
-- the Contact panel forwards messages to. Idempotent.

create table if not exists app_setting (
  key   text primary key,
  value text
);

-- Seed the contact-admin recipient. The 'on conflict do nothing'
-- preserves any custom value an admin may have set later via SQL.
insert into app_setting (key, value)
values ('contact_to', 'ai@x22.fr')
on conflict (key) do nothing;
