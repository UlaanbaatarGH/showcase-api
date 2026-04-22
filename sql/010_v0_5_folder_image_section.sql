-- FIX521.2.1.1.4: per-image "Section" field inside an item — like a
-- table-of-contents entry grouping 1..N images within the item's album.
-- Lives on folder_image (not image) because the grouping is a property of
-- the (item, image) association, not of the asset itself.
alter table folder_image
  add column if not exists section text;
