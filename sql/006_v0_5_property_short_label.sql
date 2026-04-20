-- FIX500.2.2.2.1.1.3 / <property-short-name>:
-- Optional short label used in the Showcase list column headers
-- (FIX510.2.1.1.2). Falls back to `label` in the UI when null.
alter table property
  add column if not exists short_label text;
