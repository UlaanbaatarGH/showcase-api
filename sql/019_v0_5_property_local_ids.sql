-- Showcase V0.5: project-local property ids (FIX350.2.2.2.1.1 / .1.1.1)
--
-- Renumbers property.id to the form  project_id * 1000 + N  (N = 1..999
-- per project, ordered by sort_order, then existing id) so that the
-- displayed id (= id mod 1000) starts at 1 for each project.
-- Also rewrites every JSONB reference that stores property ids:
--   folder.properties                              (keys are property ids)
--   project.view_setup.showcase.columns[].property_id
--   project.view_setup.showcase.groups[].property_id
--   project.view_setup.file_explorer.deleted_property_id
--   project.view_setup.file_explorer.date_property_id
--
-- Idempotent: if every property already fits the scheme, no rows change.


-- Helper: rewrite a project's view_setup JSONB given a remap
-- ({"old_id": new_id, ...}). Touches only the four reference sites
-- listed above; everything else passes through untouched.
create or replace function _remap_property_ids(vs jsonb, remap jsonb)
returns jsonb
language plpgsql
as $$
declare
  result jsonb := vs;
  arr jsonb;
  pid_text text;
begin
  if vs is null then
    return null;
  end if;

  -- showcase.columns[].property_id (only on type='property' columns)
  arr := result #> '{showcase, columns}';
  if jsonb_typeof(arr) = 'array' then
    select jsonb_agg(
      case when c->>'type' = 'property' and remap ? (c->>'property_id')
           then jsonb_set(c, '{property_id}', remap->(c->>'property_id'))
           else c
      end
    )
      into arr
      from jsonb_array_elements(arr) c;
    result := jsonb_set(result, '{showcase, columns}', coalesce(arr, '[]'::jsonb));
  end if;

  -- showcase.groups[].property_id
  arr := result #> '{showcase, groups}';
  if jsonb_typeof(arr) = 'array' then
    select jsonb_agg(
      case when remap ? (g->>'property_id')
           then jsonb_set(g, '{property_id}', remap->(g->>'property_id'))
           else g
      end
    )
      into arr
      from jsonb_array_elements(arr) g;
    result := jsonb_set(result, '{showcase, groups}', coalesce(arr, '[]'::jsonb));
  end if;

  -- file_explorer.deleted_property_id
  pid_text := result #>> '{file_explorer, deleted_property_id}';
  if pid_text is not null and remap ? pid_text then
    result := jsonb_set(result, '{file_explorer, deleted_property_id}', remap->pid_text);
  end if;

  -- file_explorer.date_property_id
  pid_text := result #>> '{file_explorer, date_property_id}';
  if pid_text is not null and remap ? pid_text then
    result := jsonb_set(result, '{file_explorer, date_property_id}', remap->pid_text);
  end if;

  return result;
end $$;


do $$
declare
  proj record;
  remap jsonb;
begin
  for proj in select id from project order by id loop
    -- Build the per-project remap, excluding rows whose id already
    -- matches their target — keeps the migration a true no-op when
    -- everything is already in the new scheme.
    select coalesce(jsonb_object_agg(old_id::text, new_id), '{}'::jsonb)
      into remap
      from (
        select p.id as old_id,
               proj.id * 1000 + row_number() over (order by p.sort_order, p.id) as new_id
          from property p
          join folder f on f.id = p.master_folder_id
         where f.project_id = proj.id
      ) m
     where m.old_id <> m.new_id;

    if remap = '{}'::jsonb then
      continue;
    end if;

    -- Phase 1: shift the affected rows into a high temp range so
    -- assigning final ids in Phase 2 cannot violate the PK.
    update property p
       set id = p.id + 1000000000000
      from folder f
     where p.master_folder_id = f.id
       and f.project_id = proj.id
       and remap ? p.id::text;

    -- Phase 2: assign final ids by looking up the original (pre-shift)
    -- id in the remap.
    update property p
       set id = (remap->>(p.id - 1000000000000)::text)::bigint
      from folder f
     where p.master_folder_id = f.id
       and f.project_id = proj.id
       and remap ? (p.id - 1000000000000)::text;

    -- Phase 3: rewrite folder.properties JSONB keys for this project.
    update folder f
       set properties = (
         select coalesce(
           jsonb_object_agg(
             coalesce(remap->>k.key, k.key),
             k.value
           ),
           '{}'::jsonb
         )
         from jsonb_each(f.properties) k
       )
     where f.project_id = proj.id
       and f.properties is not null
       and f.properties <> '{}'::jsonb;

    -- Phase 4: rewrite project.view_setup property-id references.
    update project
       set view_setup = _remap_property_ids(view_setup, remap)
     where id = proj.id;
  end loop;
end $$;

drop function _remap_property_ids(jsonb, jsonb);

-- Bump the bigserial sequence past every manually-allocated id so any
-- accidental default-id insert (a code path that forgot to provide an
-- explicit id) does not collide with future project_id*1000 values.
select setval(pg_get_serial_sequence('property', 'id'),
              greatest(coalesce((select max(id) from property), 1), 1));
