-- Showcase V2 / FIX317: allow app_user.id to be reassigned when a
-- placeholder row gets linked to a Supabase auth.users row during
-- account redemption (FIX317.3.1.10). Every FK pointing at
-- app_user(id) gets ON UPDATE CASCADE so the rewrite cascades.
-- Idempotent: drops + re-adds the constraints under their canonical
-- names. Safe to re-run.


alter table project_access drop constraint if exists project_access_user_id_fkey;
alter table project_access
  add constraint project_access_user_id_fkey
  foreign key (user_id) references app_user(id)
  on delete cascade on update cascade;

alter table visit drop constraint if exists visit_user_id_fkey;
alter table visit
  add constraint visit_user_id_fkey
  foreign key (user_id) references app_user(id)
  on delete cascade on update cascade;

alter table project drop constraint if exists project_owner_id_fkey;
alter table project
  add constraint project_owner_id_fkey
  foreign key (owner_id) references app_user(id)
  on delete set null on update cascade;
