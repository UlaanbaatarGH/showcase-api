-- FIX509 storage shape change: labels JSONB used to be flat
--   { 'Cancel': 'Annuler', 'Send': 'Envoyer' }
-- and is now nested by section
--   { '420. Contact panel': { 'Cancel': 'Annuler', 'Send': 'Envoyer' } }.
--
-- Wrap any pre-existing flat labels under '420. Contact panel' since
-- that's the only section the registry currently declares. After
-- migration 032 the runtime fallback in i18n.jsx that reads flat
-- top-level keys can be removed.
--
-- Idempotent: a labels row whose top-level values are already
-- objects (= already nested) is left alone. Empty labels rows are
-- left alone.

update language
set labels = jsonb_build_object('420. Contact panel', labels)
where labels != '{}'::jsonb
  and not exists (
    select 1
    from jsonb_each(labels) as e(k, v)
    where jsonb_typeof(v) = 'object'
  );
