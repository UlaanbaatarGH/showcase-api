-- Showcase V0.3: per-project view setup (properties editable, columns configurable)
-- Idempotent.

alter table project
  add column if not exists view_setup jsonb not null default '{}'::jsonb;

-- Initialize empty view_setup for existing projects with current default layout:
-- file_explorer: main_img_icon_height = 100
-- showcase columns: main_image_icon, folder_name, then every existing property in sort order
update project p
set view_setup = jsonb_build_object(
  'file_explorer', jsonb_build_object('main_img_icon_height', 100),
  'showcase', jsonb_build_object(
    'folder_column_name', null,
    'roman_year_converter', false,
    'columns', coalesce((
      select jsonb_agg(col order by ord)
      from (
        select 0 as ord, jsonb_build_object('type', 'main_image_icon') as col
        union all
        select 1, jsonb_build_object('type', 'folder_name')
        union all
        select 2 + pr.sort_order,
               jsonb_build_object('type', 'property', 'property_id', pr.id)
        from property pr
        where pr.project_id = p.id
      ) t
    ), '[]'::jsonb)
  )
)
where p.view_setup = '{}'::jsonb or p.view_setup is null;
