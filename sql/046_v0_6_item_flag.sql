-- FIX525.3.5 / <action-item-flagging>: lets a project Data Manager flag an
-- item to indicate something needs fixing. A plain per-item boolean --
-- separate from the rating system, visible to any viewer, settable only by
-- an Admin or Data Manager (enforced server-side in
-- POST /api/folders/{id}/flag). Idempotent: safe to re-run.

alter table folder
  add column if not exists is_flagged boolean not null default false;
