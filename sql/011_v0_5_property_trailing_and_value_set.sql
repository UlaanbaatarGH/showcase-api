-- FIX506.2.1.1.4 / <input-property-trailing-values>:
-- Optional comma-separated, single-quote-wrapped tokens (e.g.  '-', '?')
-- that always sort to the end of the Showcase list, regardless of sort
-- direction (FIX510.2.1.5). Stored verbatim; parsed at display time.
--
-- FIX506.2.1.1.5 / <input-property-accepted-value-set>:
-- When true, the property's value can be interpreted as a comma-separated
-- list or a "lo..hi" range (FIX506.5.5). Used by the sort logic
-- (FIX510.2.1.5) to pick the lower bound on ascending sort and the upper
-- bound on descending.
alter table property
  add column if not exists trailing_values    text,
  add column if not exists accepted_value_set boolean not null default false;
