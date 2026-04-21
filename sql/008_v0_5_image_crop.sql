-- Image crop metadata: {x, y, width, height} relative to the full image.
-- null means no crop (show the whole image). Paired with image.rotation,
-- this lets the viewer render a non-destructive edit without re-uploading
-- the asset.
alter table image
  add column if not exists crop jsonb;
