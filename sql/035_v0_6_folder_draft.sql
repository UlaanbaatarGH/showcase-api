-- FIX620.4.2.2: items created by the local app's Camera-capture feature
-- (Create item mode) start as drafts -- not returned to production callers
-- of /api/showcase -- until an image is actually confirmed/published for
-- them (see /api/images/confirm), at which point the flag is cleared and
-- the item becomes part of the normal publication.
alter table folder
  add column if not exists is_draft boolean not null default false;
