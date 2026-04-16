-- Seed data for V0.1
-- Run ONCE after 001_v0_1_schema.sql. Re-running will create duplicates.

with new_project as (
  insert into project (name) values ('Old books') returning id
),
new_folder as (
  insert into folder (project_id, name, sort_order)
  select id, '038', 1 from new_project
  returning id
),
img_cover as (
  insert into image (storage_key) values ('136-20260304_165611.jpg') returning id
),
img_title as (
  insert into image (storage_key) values ('138-20260304_165621.jpg') returning id
),
img_first as (
  insert into image (storage_key) values ('139-20260304_165645.jpg') returning id
)
insert into folder_image (folder_id, image_id, caption, is_main, sort_order)
  select new_folder.id, img_cover.id, 'Front cover', false, 1 from new_folder, img_cover
  union all
  select new_folder.id, img_title.id, 'Title page',  true,  2 from new_folder, img_title
  union all
  select new_folder.id, img_first.id, 'First page',  false, 3 from new_folder, img_first;
