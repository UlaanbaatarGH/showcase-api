-- FIX500.2.2.5.3 / FIX500.2.2.5.4: derived properties.
-- Optional formula text evaluated at display time; null = regular (stored)
-- property. Syntax: function-name(other-property-name).
alter table property
  add column if not exists formula text;
