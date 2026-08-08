-- FIX520.2.7 / FIX520.3.4 / FIX520.4.3-5: an item rating is per (item,
-- logged-in user) -- one row per user's current rating of an item.
-- Deleting the row is how '0' clears a rating (FIX520.3.4).
-- Idempotent: safe to re-run.

create table if not exists item_rating (
  id              serial primary key,
  folder_id       bigint not null references folder(id) on delete cascade,
  user_id         uuid not null references app_user(id) on delete cascade,
  rating_value_id integer not null references rating_value(id) on delete cascade,
  unique (folder_id, user_id)
);

create index if not exists item_rating_folder_idx on item_rating(folder_id);
