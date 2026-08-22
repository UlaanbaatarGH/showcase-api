-- FIX507.2.6 <field-rating-conflict-comparator>: dropdown {'<', '>'},
-- defaulted to '<'. FIX507.2.5.1 (updated): <field-rating-conflict-
-- threshold>'s default changes from 2 to 3. Existing rows keep whatever
-- threshold they already have -- only the column default (applied to
-- future rows without an explicit value) changes.
-- Idempotent: safe to re-run.

alter table project
  add column if not exists rating_conflict_comparator text not null default '<',
  alter column rating_conflict_threshold set default 3;

alter table project
  drop constraint if exists project_rating_conflict_comparator_check;
alter table project
  add constraint project_rating_conflict_comparator_check
    check (rating_conflict_comparator in ('<', '>'));
