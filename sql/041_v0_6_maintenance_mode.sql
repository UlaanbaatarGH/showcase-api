-- Showcase V0.6: FIX410.1.1.6 <website-In-maintenance> flag.
-- Reuses the generic app_setting key/value table (see 025). Idempotent.

insert into app_setting (key, value)
values ('maintenance_mode', 'false')
on conflict (key) do nothing;
