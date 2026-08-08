-- FIX507: item rating setup -- a project-level enable flag, a list of
-- rating values (text + icon), and the list of users allowed to rate
-- items, sourced from users having admin or data-manager rights on the
-- project (FIX507.2.3.1.12.1).
-- Idempotent: safe to re-run.

alter table project
  add column if not exists enable_rating boolean not null default false;

create table if not exists rating_value (
  id         serial primary key,
  project_id bigint not null references project(id) on delete cascade,
  text       text not null,
  icon       text,
  sort_order integer not null default 0
);

create index if not exists rating_value_project_idx
  on rating_value(project_id, sort_order);

-- FIX507.4.3: a project_rater row is disabled (not deleted) when the
-- user loses project access or data-manager rights, so past rating
-- data tied to user_id survives until the row is explicitly removed
-- from <table-users-allowed-to-rate>.
create table if not exists project_rater (
  id         serial primary key,
  project_id bigint not null references project(id) on delete cascade,
  user_id    uuid not null references app_user(id) on delete cascade,
  acronym    text,
  enabled    boolean not null default true,
  unique (project_id, user_id)
);
