import os
import json
import time
import base64
import traceback
import mimetypes
from contextlib import contextmanager
from typing import Optional
import urllib.request
import urllib.error
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]
SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SUPABASE_BUCKET = os.environ.get("SUPABASE_BUCKET", "showcase-images")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")  # required for /api/publish
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY")  # required for authenticated endpoints
ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,https://showcase.x22.fr,https://showcase-omega-jade.vercel.app",
).split(",")


def public_image_url(storage_key: str) -> str:
    return f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_BUCKET}/{storage_key}"


def upload_to_bucket(storage_key: str, data: bytes, content_type: str) -> None:
    if not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(
            status_code=503,
            detail="Bucket uploads disabled: SUPABASE_SERVICE_ROLE_KEY not set",
        )
    url = f"{SUPABASE_URL}/storage/v1/object/{SUPABASE_BUCKET}/{storage_key}"
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
            "Content-Type": content_type or "application/octet-stream",
            "x-upsert": "true",
            "Cache-Control": "public, max-age=31536000, immutable",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise HTTPException(
            status_code=502,
            detail=f"Bucket upload failed ({e.code}): {body[:500]}",
        )
    except urllib.error.URLError as e:
        raise HTTPException(status_code=502, detail=f"Bucket upload error: {e}")

pool = ConnectionPool(
    conninfo=DATABASE_URL,
    min_size=1,
    max_size=5,
    open=False,
    # Supabase's pooler (port 6543) runs pgBouncer in transaction mode. Server
    # connections are reused between clients, which breaks server-side
    # prepared statements — psycopg3 caches statement names per client conn
    # but the server-side slot can already be taken. Disable auto-preparation
    # by passing prepare_threshold=None to every Connection.connect().
    kwargs={"prepare_threshold": None},
)

app = FastAPI()


@app.on_event("startup")
def on_startup():
    pool.open()


@app.on_event("shutdown")
def on_shutdown():
    pool.close()


app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in ALLOWED_ORIGINS],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {"status": "ok"}


# ============================================================
# FIX310 + FIX300: auth helpers (Supabase JWT verification)
# ============================================================
def _verify_token(token: str) -> dict:
    # Validate the access token by asking Supabase directly. This works
    # regardless of the project's signing algorithm (HS256 legacy, ES256 new
    # asymmetric keys) and avoids having to manage a shared JWT secret.
    if not SUPABASE_ANON_KEY:
        raise HTTPException(status_code=503, detail="auth not configured")
    req = urllib.request.Request(
        f"{SUPABASE_URL}/auth/v1/user",
        headers={
            "Authorization": f"Bearer {token}",
            "apikey": SUPABASE_ANON_KEY,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=401, detail=f"invalid token ({e.code}): {body[:200]}")
    except urllib.error.URLError as e:
        raise HTTPException(status_code=502, detail=f"auth verify error: {e}")


def current_user_optional(request: Request) -> Optional[dict]:
    """Returns {id, email} if a valid bearer token is present, None otherwise."""
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        return None
    user = _verify_token(auth.split(" ", 1)[1].strip())
    return {"id": user.get("id"), "email": user.get("email")}


def current_user_required(request: Request) -> dict:
    user = current_user_optional(request)
    if not user:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


# ============================================================
# FIX310: users
# ============================================================
@app.post("/api/users/me")
async def upsert_me(request: Request, user=Depends(current_user_required)):
    """Create or refresh this signed-in user's app_user row.
    Call after Supabase sign-up/sign-in so the backend knows about the user.
    Payload: {"login_name": "chosen handle"} — only used on first insert.
    """
    payload = await request.json() if await request.body() else {}
    login_name = (payload.get("login_name") or user["email"] or user["id"]).strip()

    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "insert into app_user (id, login_name) values (%s, %s) "
                "on conflict (id) do update set login_name = app_user.login_name "
                "returning id, login_name, profile, created_at",
                (user["id"], login_name),
            )
            row = cur.fetchone()
            # FIX410.1.1.1.1: log this session activation as a visit. Fires
            # on every fresh sign-in and on each page reload that picks up
            # an existing Supabase session — close enough to "user shows
            # up" for the Admin > Visits panel.
            cur.execute(
                "insert into visit (user_id) values (%s)",
                (user["id"],),
            )
        conn.commit()
    return row


@app.get("/api/users/me")
def get_me(user=Depends(current_user_required)):
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select id, login_name, profile, created_at "
                "from app_user where id = %s",
                (user["id"],),
            )
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="user row not created yet")
    return row


# ============================================================
# FIX410.1.1.1.1: admin Visits panel — list users that signed in
# with date/time, most recent first.
# ============================================================
@app.get("/api/admin/visits")
def list_visits(_user=Depends(current_user_required)):
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select u.login_name, v.ts "
                "from visit v "
                "join app_user u on u.id = v.user_id "
                "order by v.ts desc "
                "limit 200"
            )
            rows = cur.fetchall()
    # Serialize timestamps as ISO strings so the JSON response is portable.
    return [{"login_name": r["login_name"], "ts": r["ts"].isoformat()} for r in rows]


# ============================================================
# FIX400: list projects visible to caller
# ============================================================
@app.get("/api/projects")
def list_projects(user=Depends(current_user_optional)):
    """
    FIX400.4.1: anonymous callers see only public projects.
    FIX400.4.2: signed-in callers also see private projects they own
                or have any project_access row for.
    """
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            if user is None:
                cur.execute(
                    "select id, name, cover_image_key, is_public, "
                    "       false as can_edit "
                    "from project where is_public "
                    "order by name, id"
                )
            else:
                # FIX400.3.2.1 / FIX400.4.3: can_edit flags projects the
                # signed-in user is allowed to rename / re-cover. True when
                # the user is the owner OR the project is unowned
                # (owner_id IS NULL) — the first successful edit auto-claims
                # ownership in PATCH /api/projects/:id below.
                cur.execute(
                    "select distinct p.id, p.name, p.cover_image_key, p.is_public, "
                    "       (p.owner_id = %s or p.owner_id is null) as can_edit "
                    "from project p "
                    "left join project_access pa "
                    "       on pa.project_id = p.id and pa.user_id = %s "
                    "where p.is_public "
                    "   or pa.user_id is not null "
                    "   or p.owner_id = %s "
                    "order by p.name, p.id",
                    (user["id"], user["id"], user["id"]),
                )
            rows = cur.fetchall()
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "is_public": r["is_public"],
            "can_edit": bool(r["can_edit"]),
            "cover_image_url": (
                public_image_url(r["cover_image_key"]) if r["cover_image_key"] else None
            ),
        }
        for r in rows
    ]


# FIX400.3.3 + FIX400.3.2.1.1: rename a project and/or replace its cover
# image. Owner-only. Payload accepts any subset of {name, cover_image_key}.
@app.patch("/api/projects/{project_id}")
async def update_project(
    project_id: int,
    request: Request,
    user=Depends(current_user_required),
):
    payload = await request.json()
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select owner_id from project where id = %s", (project_id,)
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="project not found")
            # Allow: owner, or anyone if the project is still unowned — in
            # which case we auto-claim ownership below so subsequent edits
            # stick to this user.
            if row["owner_id"] is not None and row["owner_id"] != user["id"]:
                raise HTTPException(status_code=403, detail="not owner")
            auto_claim = row["owner_id"] is None

            updates: list[str] = []
            params: list = []
            if "name" in payload:
                name = payload.get("name")
                if not isinstance(name, str) or not name.strip():
                    raise HTTPException(status_code=400, detail="name must be a non-empty string")
                updates.append("name = %s")
                params.append(name.strip())
            if "cover_image_key" in payload:
                cover = payload.get("cover_image_key")
                if cover is not None and not isinstance(cover, str):
                    raise HTTPException(status_code=400, detail="cover_image_key must be string or null")
                updates.append("cover_image_key = %s")
                params.append(cover)
            if auto_claim:
                updates.append("owner_id = %s")
                params.append(user["id"])
            if not updates:
                raise HTTPException(status_code=400, detail="nothing to update")

            cur.execute(
                f"update project set {', '.join(updates)} where id = %s "
                "returning id, name, cover_image_key, is_public",
                (*params, project_id),
            )
            r = cur.fetchone()
        conn.commit()
    return {
        "id": r["id"],
        "name": r["name"],
        "is_public": r["is_public"],
        "cover_image_url": (
            public_image_url(r["cover_image_key"]) if r["cover_image_key"] else None
        ),
    }


# FIX400.3.2.1.2: request a signed upload URL for a new project cover
# image. The client PUTs the bytes directly to Supabase, then calls
# PATCH /api/projects/:id with the returned storage_key.
@app.post("/api/projects/{project_id}/sign-cover-upload")
async def sign_project_cover_upload(
    project_id: int,
    request: Request,
    user=Depends(current_user_required),
):
    payload = await request.json()
    filename = payload.get("filename") or ""
    if not filename:
        raise HTTPException(status_code=400, detail="filename required")

    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select owner_id from project where id = %s", (project_id,)
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="project not found")
            # Same relaxed owner check as PATCH — unowned projects can be
            # edited by any signed-in user. The PATCH that follows will
            # auto-claim ownership on save.
            if row["owner_id"] is not None and row["owner_id"] != user["id"]:
                raise HTTPException(status_code=403, detail="not owner")

    # Versioned key so browser caches of the public URL are invalidated
    # when the cover is replaced. Matches the convention used for content
    # images (see /api/images/confirm).
    timestamp = int(time.time())
    base, _, ext = _sanitize_path_segment(filename).rpartition(".")
    if not base:
        base, ext = _sanitize_path_segment(filename), ""
    storage_key = (
        f"p{int(project_id)}/_cover/{base}_{timestamp}.{ext}"
        if ext else f"p{int(project_id)}/_cover/{base}_{timestamp}"
    )
    url = f"{SUPABASE_URL}/storage/v1/object/upload/sign/{SUPABASE_BUCKET}/{storage_key}"
    req = urllib.request.Request(
        url,
        method="POST",
        headers={
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
            "Content-Type": "application/json",
        },
        data=b"{}",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=502, detail=f"Supabase sign failed: {body[:200]}")
    except urllib.error.URLError as e:
        raise HTTPException(status_code=502, detail=f"Supabase sign failed: {e}")
    signed_path = result.get("url") or ""
    signed_url = f"{SUPABASE_URL}/storage/v1{signed_path}"
    return {"storage_key": storage_key, "signed_url": signed_url}


@app.get("/api/hello")
def hello():
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select id, message from hello order by id limit 1")
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="no hello row")
    return row


@app.get("/api/showcase")
def showcase():
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select id, name, view_setup from project order by id limit 1"
            )
            project = cur.fetchone()
            if not project:
                return {
                    "project": None,
                    "properties": [],
                    "view_setup": {},
                    "folders": [],
                }
            # FIX350.2.3.1: property list lives on Master Folder, not project.
            # A project can have several Master Folders (FIX350.2.3.3); we union
            # their properties here for the showcase view.
            cur.execute(
                "select p.id, p.label, p.short_label, p.formula, "
                "       p.trailing_values, p.accepted_value_set, p.sort_order "
                "from property p "
                "join folder f on f.id = p.master_folder_id "
                "where f.project_id = %s and f.is_master "
                "order by p.sort_order, p.id",
                (project["id"],),
            )
            properties = cur.fetchall()
            cur.execute(
                """
                select
                  f.id,
                  f.name,
                  f.note,
                  f.sort_order,
                  f.properties,
                  img.storage_key as main_storage_key,
                  img.rotation    as main_rotation,
                  exists (select 1 from folder_image where folder_id = f.id) as has_image
                from folder f
                left join folder_image fi on fi.folder_id = f.id and fi.is_main
                left join image img       on img.id = fi.image_id
                where f.project_id = %s
                order by f.sort_order, f.id
                """,
                (project["id"],),
            )
            rows = cur.fetchall()
    folders = [
        {
            "id": r["id"],
            "name": r["name"],
            "note": r["note"],
            "sort_order": r["sort_order"],
            "properties": r["properties"] or {},
            "main_image_url": (
                public_image_url(r["main_storage_key"]) if r["main_storage_key"] else None
            ),
            "main_rotation": r["main_rotation"],
            "has_image": bool(r["has_image"]),
        }
        for r in rows
    ]
    return {
        "project": {"id": project["id"], "name": project["name"]},
        "properties": properties,
        "view_setup": project["view_setup"] or {},
        "folders": folders,
    }


@app.post("/api/setup")
async def save_setup(request: Request):
    payload = await request.json()
    try:
        return _save_setup_impl(payload)
    except HTTPException:
        raise
    except Exception as e:
        tb = traceback.format_exc()
        print("save_setup failed:\n" + tb, flush=True)
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")


def _save_setup_impl(payload):
    incoming_props = payload.get("properties", [])
    view_setup = payload.get("view_setup", {}) or {}

    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select id from project order by id limit 1")
            project = cur.fetchone()
            if not project:
                raise HTTPException(status_code=404, detail="no project")
            project_id = project["id"]

            # FIX350.2.3.1: properties belong to a Master Folder. /api/setup
            # currently edits a single project's list; we target the one Master
            # Folder. If multiple Master Folders exist (FIX350.2.3.3), the
            # endpoint needs a master_folder_id param — TODO when multi-Master
            # editing UI lands.
            cur.execute(
                "select id from folder "
                "where project_id = %s and is_master "
                "order by id limit 1",
                (project_id,),
            )
            master = cur.fetchone()
            if not master:
                raise HTTPException(
                    status_code=500,
                    detail="project has no Master Folder; run migration 005",
                )
            master_folder_id = master["id"]

            cur.execute(
                "select id from property where master_folder_id = %s",
                (master_folder_id,),
            )
            existing_ids = {r["id"] for r in cur.fetchall()}
            incoming_existing_ids = {
                p["id"] for p in incoming_props if isinstance(p.get("id"), int)
            }
            id_mapping = {}  # placeholder id → new real id

            def _clean_optional(raw):
                return (
                    raw.strip() if isinstance(raw, str) and raw.strip() else None
                )

            for idx, p in enumerate(incoming_props):
                label = (p.get("label") or "").strip()
                if not label:
                    continue
                sort_order = p.get("sort_order", idx)
                # Optional fields (FIX500.2.2.2.1.1.3 / FIX500.2.2.5.3.2):
                # presence check — if the caller didn't include the key we
                # leave the existing DB value alone. This matters because
                # panels that aren't the property editor (GroupingPanel,
                # grouping defaults, etc.) call /api/setup with only a slim
                # properties payload and previously wiped these fields.
                has_short = "short_label" in p
                has_formula = "formula" in p
                # FIX506.2.1.1.4 / FIX506.2.1.1.5: same presence-check
                # pattern as short_label/formula. Slim-payload callers
                # (GroupingPanel, etc.) omit these keys → existing DB
                # values are preserved.
                has_trailing = "trailing_values" in p
                has_value_set = "accepted_value_set" in p
                short_label = _clean_optional(p.get("short_label")) if has_short else None
                formula = _clean_optional(p.get("formula")) if has_formula else None
                trailing_values = (
                    _clean_optional(p.get("trailing_values")) if has_trailing else None
                )
                accepted_value_set = bool(p.get("accepted_value_set")) if has_value_set else False
                if isinstance(p.get("id"), int) and p["id"] in existing_ids:
                    set_parts = ["label = %s", "sort_order = %s"]
                    params = [label, sort_order]
                    if has_short:
                        set_parts.append("short_label = %s")
                        params.append(short_label)
                    if has_formula:
                        set_parts.append("formula = %s")
                        params.append(formula)
                    if has_trailing:
                        set_parts.append("trailing_values = %s")
                        params.append(trailing_values)
                    if has_value_set:
                        set_parts.append("accepted_value_set = %s")
                        params.append(accepted_value_set)
                    params.append(p["id"])
                    cur.execute(
                        f"update property set {', '.join(set_parts)} where id = %s",
                        params,
                    )
                else:
                    cur.execute(
                        "insert into property "
                        "  (master_folder_id, label, short_label, formula, "
                        "   trailing_values, accepted_value_set, sort_order) "
                        "values (%s, %s, %s, %s, %s, %s, %s) returning id",
                        (
                            master_folder_id,
                            label,
                            short_label,
                            formula,
                            trailing_values,
                            accepted_value_set,
                            sort_order,
                        ),
                    )
                    new_id = cur.fetchone()["id"]
                    if p.get("id") is not None:
                        id_mapping[p["id"]] = new_id

            to_delete = existing_ids - incoming_existing_ids
            for pid in to_delete:
                cur.execute(
                    "update folder set properties = properties - %s "
                    "where project_id = %s",
                    (str(pid), project_id),
                )
            if to_delete:
                cur.execute(
                    "delete from property where id = any(%s)",
                    (list(to_delete),),
                )

            showcase_cfg = view_setup.get("showcase", {}) or {}
            columns = showcase_cfg.get("columns", []) or []
            filtered_columns = []
            for col in columns:
                if col.get("type") == "property":
                    pid = col.get("property_id")
                    if pid in id_mapping:
                        pid = id_mapping[pid]
                    if not isinstance(pid, int) or pid in to_delete:
                        continue
                    col = {**col, "property_id": pid}
                filtered_columns.append(col)
            showcase_cfg["columns"] = filtered_columns
            view_setup["showcase"] = showcase_cfg

            cur.execute(
                "update project set view_setup = %s::jsonb where id = %s",
                (json.dumps(view_setup), project_id),
            )
            cur.execute(
                "select id, label, short_label, formula, "
                "       trailing_values, accepted_value_set, sort_order "
                "from property where master_folder_id = %s order by sort_order, id",
                (master_folder_id,),
            )
            fresh_properties = cur.fetchall()
        conn.commit()
    return {"properties": fresh_properties, "view_setup": view_setup}


# ============================================================
# FIX370: Google Sheet import — one transactional endpoint
# ============================================================
@app.post("/api/projects/{project_id}/import-gsheet")
async def import_gsheet(
    project_id: int,
    request: Request,
    user=Depends(current_user_required),
):
    """Bulk apply a validated gsheet import plan.

    Payload:
    {
      "new_properties": ["Writer", "Genre"],
      "renames": [{"id": 5, "label": "Writer"}],
      "new_folders": ["F001", "F002"],
      "updates": [
        {"folder_name": "F001", "property_label": "Writer", "value": "Hugo"}
      ]
    }
    No deletion: rows removed from the sheet never delete folders or
    properties. All folders go under the project's (single) Master Folder.
    """
    payload = await request.json()
    new_properties = payload.get("new_properties") or []
    renames = payload.get("renames") or []
    new_folders = payload.get("new_folders") or []
    updates = payload.get("updates") or []

    try:
        return _apply_gsheet_plan(project_id, new_properties, renames, new_folders, updates)
    except HTTPException:
        raise
    except Exception as e:
        # Surface the actual error to the frontend instead of a bare 500 so
        # the import dialog can show something actionable.
        tb = traceback.format_exc()
        print("import-gsheet failed:\n" + tb, flush=True)
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")


def _apply_gsheet_plan(project_id, new_properties, renames, new_folders, updates):
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select id from project where id = %s", (project_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="project not found")

            cur.execute(
                "select id from folder "
                "where project_id = %s and is_master "
                "order by id limit 1",
                (project_id,),
            )
            master = cur.fetchone()
            if not master:
                raise HTTPException(
                    status_code=500,
                    detail="project has no Master Folder",
                )
            master_folder_id = master["id"]

            # 1) new properties
            cur.execute(
                "select coalesce(max(sort_order), -1) as m from property "
                "where master_folder_id = %s",
                (master_folder_id,),
            )
            next_sort = (cur.fetchone()["m"] or -1) + 1
            new_prop_ids = {}
            # FIX370.1.2.1.3 / <property-short-name>: each new property may
            # carry a `short_label` alongside its `label`. Accept both the
            # new object shape [{label, short_label}] and the legacy string
            # shape so older callers still work.
            for entry in new_properties:
                if isinstance(entry, dict):
                    label = (entry.get("label") or "").strip()
                    raw_short = entry.get("short_label")
                    short_label = (
                        raw_short.strip()
                        if isinstance(raw_short, str) and raw_short.strip()
                        else None
                    )
                else:
                    label = (entry or "").strip()
                    short_label = None
                if not label:
                    continue
                cur.execute(
                    "insert into property (master_folder_id, label, short_label, sort_order) "
                    "values (%s, %s, %s, %s) returning id",
                    (master_folder_id, label, short_label, next_sort),
                )
                new_prop_ids[label] = cur.fetchone()["id"]
                next_sort += 1

            # 2) renames
            for r in renames:
                cur.execute(
                    "update property set label = %s "
                    "where id = %s and master_folder_id = %s",
                    (r["label"], r["id"], master_folder_id),
                )

            # 3) new folders (as children of the master folder)
            cur.execute(
                "select coalesce(max(sort_order), -1) as m from folder "
                "where project_id = %s and parent_id = %s",
                (project_id, master_folder_id),
            )
            next_fsort = (cur.fetchone()["m"] or -1) + 1
            new_folder_ids = {}
            for fname in new_folders:
                cur.execute(
                    "insert into folder (project_id, parent_id, name, sort_order) "
                    "values (%s, %s, %s, %s) returning id",
                    (project_id, master_folder_id, fname, next_fsort),
                )
                new_folder_ids[fname] = cur.fetchone()["id"]
                next_fsort += 1

            # 4) lookup tables for updates
            cur.execute(
                "select id, label from property where master_folder_id = %s",
                (master_folder_id,),
            )
            label_to_prop = {r["label"]: r["id"] for r in cur.fetchall()}
            cur.execute(
                "select id, name from folder where project_id = %s",
                (project_id,),
            )
            name_to_folder = {r["name"]: r["id"] for r in cur.fetchall()}

            # 5) aggregate and merge updates into folder.properties JSONB
            per_folder = {}
            for u in updates:
                fid = name_to_folder.get(u.get("folder_name"))
                pid = label_to_prop.get(u.get("property_label"))
                if fid is None or pid is None:
                    continue
                per_folder.setdefault(fid, {})[str(pid)] = u.get("value", "") or ""

            for fid, merge_map in per_folder.items():
                cur.execute(
                    "update folder set "
                    "properties = coalesce(properties, '{}'::jsonb) || %s::jsonb "
                    "where id = %s",
                    (json.dumps(merge_map), fid),
                )

        conn.commit()
    return {
        "new_properties_count": len(new_prop_ids),
        "renames_count": len(renames),
        "new_folders_count": len(new_folder_ids),
        "updated_folders_count": len(per_folder),
    }


@app.post("/api/publish")
async def publish_folder(request: Request):
    """One-way push: local folder → cloud database + bucket.

    Payload shape:
    {
      "folder": {
        "name": "038",
        "note": null,
        "sort_order": 1,
        "properties": {"1": "Victor Hugo", "3": "1862"}  // keyed by property id
      },
      "images": [
        {
          "filename": "136-20260304_165611.jpg",
          "caption": "Front cover",
          "is_main": false,
          "sort_order": 1,
          "rotation": 0,
          "data_base64": "...binary..."
        }
      ]
    }

    Creates a new folder row (re-publish creates duplicates for now — we match
    by folder.name within the one project). Each image is uploaded under a
    versioned storage_key: "<base>_<epoch_seconds>.<ext>".
    """
    payload = await request.json()
    folder_payload = payload.get("folder") or {}
    images_payload = payload.get("images") or []

    name = (folder_payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="folder.name is required")

    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select id from project order by id limit 1")
            project = cur.fetchone()
            if not project:
                raise HTTPException(status_code=404, detail="no project")
            project_id = project["id"]

            # Find or create folder by name within project.
            cur.execute(
                "select id from folder where project_id = %s and name = %s",
                (project_id, name),
            )
            existing = cur.fetchone()
            if existing:
                folder_id = existing["id"]
                cur.execute(
                    "update folder set note = %s, sort_order = %s, properties = %s::jsonb "
                    "where id = %s",
                    (
                        folder_payload.get("note"),
                        folder_payload.get("sort_order", 0),
                        json.dumps(folder_payload.get("properties") or {}),
                        folder_id,
                    ),
                )
                # Drop previous folder_image links; images rows remain
                cur.execute("delete from folder_image where folder_id = %s", (folder_id,))
            else:
                cur.execute(
                    "insert into folder (project_id, name, note, sort_order, properties) "
                    "values (%s, %s, %s, %s, %s::jsonb) returning id",
                    (
                        project_id,
                        name,
                        folder_payload.get("note"),
                        folder_payload.get("sort_order", 0),
                        json.dumps(folder_payload.get("properties") or {}),
                    ),
                )
                folder_id = cur.fetchone()["id"]

            timestamp = int(time.time())
            uploaded = []
            for idx, img in enumerate(images_payload):
                filename = (img.get("filename") or "").strip()
                if not filename:
                    continue
                base, _, ext = filename.rpartition(".")
                if not base:
                    base, ext = filename, ""
                storage_key = f"{base}_{timestamp}.{ext}" if ext else f"{base}_{timestamp}"
                content_type = (
                    mimetypes.guess_type(filename)[0] or "application/octet-stream"
                )
                data_b64 = img.get("data_base64") or ""
                try:
                    raw = base64.b64decode(data_b64, validate=False)
                except Exception as e:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Could not decode image {filename}: {e}",
                    )
                upload_to_bucket(storage_key, raw, content_type)

                cur.execute(
                    "insert into image (storage_key, rotation) values (%s, %s) returning id",
                    (storage_key, img.get("rotation", 0)),
                )
                image_id = cur.fetchone()["id"]
                cur.execute(
                    "insert into folder_image "
                    "(folder_id, image_id, caption, is_main, sort_order) "
                    "values (%s, %s, %s, %s, %s)",
                    (
                        folder_id,
                        image_id,
                        img.get("caption"),
                        bool(img.get("is_main", False)),
                        img.get("sort_order", idx),
                    ),
                )
                uploaded.append({"filename": filename, "storage_key": storage_key})
        conn.commit()
    return {"folder_id": folder_id, "uploaded": uploaded}


# ============================================================
# FIX507: storage size for the project's images
# ============================================================
@app.get("/api/projects/{project_id}/storage-size")
def storage_size(project_id: int):
    """Return the total bytes consumed in Supabase Storage by all images
    linked to folders of this project. Reads `storage.objects.metadata`
    (managed by Supabase Storage) so old uploads count too — no per-image
    size column is needed in our `image` table.
    Returns: { bytes, image_count, missing_count }
      - bytes: sum of file sizes for matched objects
      - image_count: total folder_image rows for this project
      - missing_count: image rows with no matching storage object (e.g.
        upload pending or storage_key drift)
    """
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                with proj_imgs as (
                    select i.id as image_id, i.storage_key
                      from image i
                      join folder_image fi on fi.image_id = i.id
                      join folder f       on f.id = fi.folder_id
                     where f.project_id = %s
                )
                select
                  coalesce(sum((o.metadata->>'size')::bigint), 0) as bytes,
                  count(distinct pi.image_id)                      as image_count,
                  count(distinct pi.image_id) filter (where o.id is null) as missing_count
                from proj_imgs pi
                left join storage.objects o
                  on o.bucket_id = %s and o.name = pi.storage_key
                """,
                (project_id, SUPABASE_BUCKET),
            )
            row = cur.fetchone() or {}
    return {
        "bytes": int(row.get("bytes") or 0),
        "image_count": int(row.get("image_count") or 0),
        "missing_count": int(row.get("missing_count") or 0),
    }


# ============================================================
# FIX371: image import from disk — existing images listing + signed upload
# ============================================================
@app.get("/api/projects/{project_id}/existing-images")
def existing_images(project_id: int, user=Depends(current_user_required)):
    """Return all folder_image rows under a project, grouped by item name.
    The import-images client uses this to classify each disk file as
    new / updated / ignored against what is already linked.
    """
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                select f.name as folder_name, fi.id as folder_image_id,
                       fi.image_id, img.storage_key
                  from folder f
                  join folder_image fi on fi.folder_id = f.id
                  join image img on img.id = fi.image_id
                 where f.project_id = %s
                """,
                (project_id,),
            )
            rows = cur.fetchall()
    by_item = {}
    for r in rows:
        by_item.setdefault(r["folder_name"], []).append({
            "folder_image_id": r["folder_image_id"],
            "image_id": r["image_id"],
            "storage_key": r["storage_key"],
        })
    return {"items": by_item}


def _sanitize_path_segment(s: str) -> str:
    # Keep ASCII letters/digits/_/-/. — replace the rest with '_' so the
    # bucket path stays valid across all storage backends.
    import re as _re
    return _re.sub(r"[^a-zA-Z0-9._-]", "_", s or "")


def _bucket_delete(storage_key: str) -> None:
    """Delete a single object from the bucket. 404 is treated as success
    (already gone). Raises HTTPException on any other failure."""
    if not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=503, detail="bucket access not configured")
    url = f"{SUPABASE_URL}/storage/v1/object/{SUPABASE_BUCKET}/{storage_key}"
    req = urllib.request.Request(
        url,
        method="DELETE",
        headers={
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return
        body = e.read().decode("utf-8", errors="replace")
        raise HTTPException(
            status_code=502,
            detail=f"Bucket delete failed ({e.code}): {body[:200]}",
        )


def _has_image_row(storage_key: str) -> bool:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select 1 from image where storage_key = %s limit 1",
                (storage_key,),
            )
            return cur.fetchone() is not None


@app.post("/api/images/sign-upload")
async def sign_upload(request: Request, user=Depends(current_user_required)):
    if not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=503, detail="bucket uploads not configured")
    payload = await request.json()
    project_id = payload.get("project_id")
    item_name = payload.get("item_name") or ""
    filename = payload.get("filename") or ""
    if not project_id or not item_name or not filename:
        raise HTTPException(status_code=400, detail="project_id, item_name, filename required")
    storage_key = (
        f"p{int(project_id)}/"
        f"{_sanitize_path_segment(item_name)}/"
        f"{_sanitize_path_segment(filename)}"
    )

    def _request_signed_upload():
        url = f"{SUPABASE_URL}/storage/v1/object/upload/sign/{SUPABASE_BUCKET}/{storage_key}"
        req = urllib.request.Request(
            url,
            method="POST",
            headers={
                "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
                "apikey": SUPABASE_SERVICE_ROLE_KEY,
                "Content-Type": "application/json",
            },
            data=b"{}",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    try:
        result = _request_signed_upload()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        # FIX371 orphan recovery: when the bucket says the object already
        # exists but no image row references it, the file is an orphan
        # from a previous failed upload (e.g. PUT succeeded but confirm
        # never ran). Delete the orphan and retry the sign once. If a
        # row DOES exist, the key is in legitimate use — surface the
        # error so the caller doesn't overwrite live data.
        is_dup = '"statusCode":"409"' in body or '"Duplicate"' in body
        if is_dup and not _has_image_row(storage_key):
            _bucket_delete(storage_key)
            try:
                result = _request_signed_upload()
            except urllib.error.HTTPError as e2:
                body2 = e2.read().decode("utf-8", errors="replace")
                raise HTTPException(
                    status_code=502,
                    detail=f"Sign upload failed after orphan cleanup ({e2.code}): {body2[:200]}",
                )
        else:
            raise HTTPException(
                status_code=502,
                detail=f"Sign upload failed ({e.code}): {body[:300]}",
            )
    signed_path = result.get("url") or ""
    signed_url = f"{SUPABASE_URL}/storage/v1{signed_path}"
    return {"storage_key": storage_key, "signed_url": signed_url}


@app.post("/api/images/delete-orphan")
async def delete_orphan_image(request: Request, user=Depends(current_user_required)):
    """FIX371 cleanup: delete a bucket object that the client believes
    is an orphan (e.g. its confirm-image call failed mid-upload). Refuses
    to delete keys referenced by any image DB row, and only allows keys
    under p{project_id}/ as a basic ownership safeguard.
    """
    payload = await request.json()
    project_id = payload.get("project_id")
    storage_key = payload.get("storage_key")
    if not project_id or not storage_key:
        raise HTTPException(status_code=400, detail="project_id and storage_key required")
    expected_prefix = f"p{int(project_id)}/"
    if not str(storage_key).startswith(expected_prefix):
        raise HTTPException(status_code=400, detail="storage_key does not match project_id")
    if _has_image_row(storage_key):
        raise HTTPException(status_code=409, detail="storage_key is referenced by a DB row")
    _bucket_delete(storage_key)
    return {"deleted": True}


@app.post("/api/images/confirm")
async def confirm_image(request: Request, user=Depends(current_user_required)):
    payload = await request.json()
    project_id = payload.get("project_id")
    item_name = (payload.get("item_name") or "").strip()
    storage_key = payload.get("storage_key")
    sort_order = payload.get("sort_order", 0)
    caption = payload.get("caption")
    replaces_image_id = payload.get("replaces_image_id")
    if not project_id or not item_name or not storage_key:
        raise HTTPException(status_code=400, detail="project_id, item_name, storage_key required")

    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select id from folder where project_id = %s and name = %s",
                (project_id, item_name),
            )
            row = cur.fetchone()
            if row:
                folder_id = row["id"]
            else:
                # FIX371.6.1: auto-create the item if the id isn't known.
                cur.execute(
                    "select id from folder where project_id = %s and is_master order by id limit 1",
                    (project_id,),
                )
                master = cur.fetchone()
                if not master:
                    raise HTTPException(status_code=500, detail="project has no Master Folder")
                cur.execute(
                    "select coalesce(max(sort_order), -1) as m from folder "
                    "where project_id = %s and parent_id = %s",
                    (project_id, master["id"]),
                )
                next_fsort = (cur.fetchone()["m"] or -1) + 1
                cur.execute(
                    "insert into folder (project_id, parent_id, name, sort_order) "
                    "values (%s, %s, %s, %s) returning id",
                    (project_id, master["id"], item_name, next_fsort),
                )
                folder_id = cur.fetchone()["id"]

            cur.execute(
                "insert into image (storage_key) values (%s) returning id",
                (storage_key,),
            )
            image_id = cur.fetchone()["id"]

            if replaces_image_id:
                cur.execute(
                    "update folder_image set image_id = %s "
                    "where folder_id = %s and image_id = %s",
                    (image_id, folder_id, replaces_image_id),
                )
            else:
                cur.execute(
                    "insert into folder_image (folder_id, image_id, sort_order, caption) "
                    "values (%s, %s, %s, %s)",
                    (folder_id, image_id, sort_order, caption),
                )
        conn.commit()
    return {"image_id": image_id, "folder_id": folder_id}


@app.get("/api/folders/{folder_id}/images")
def list_folder_images(folder_id: int):
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select 1 from folder where id = %s", (folder_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="folder not found")
            cur.execute(
                """
                select
                  fi.id,
                  fi.caption,
                  fi.section,
                  fi.is_main,
                  fi.sort_order,
                  img.id          as image_id,
                  img.storage_key,
                  img.rotation,
                  img.crop
                from folder_image fi
                join image img on img.id = fi.image_id
                where fi.folder_id = %s
                order by fi.sort_order, fi.id
                """,
                (folder_id,),
            )
            rows = cur.fetchall()
    return [
        {
            "id": r["id"],
            "image_id": r["image_id"],
            "caption": r["caption"],
            "section": r["section"],
            "is_main": r["is_main"],
            "sort_order": r["sort_order"],
            # FIX521.2.1.1.1: "File name" column. storage_key is
            # "pN/<item>/<filename>"; the basename is what the user
            # originally uploaded (with the versioning suffix appended).
            "filename": r["storage_key"].rsplit("/", 1)[-1],
            "url": public_image_url(r["storage_key"]),
            "rotation": r["rotation"],
            "crop": r["crop"],
        }
        for r in rows
    ]


# FIX521.2.1.1.3 / .1.1.4 / .3.1 / .3.2: caption, section and sort_order
# live on folder_image (per-association), so edits from the Image List
# editor go here rather than /api/images. Accepts any subset of
# {caption, section, sort_order}; omitted keys are left untouched.
@app.patch("/api/folder-images/{folder_image_id}")
async def update_folder_image(
    folder_image_id: int,
    request: Request,
    user=Depends(current_user_required),
):
    payload = await request.json()
    updates: list[str] = []
    params: list = []

    if "caption" in payload:
        caption = payload.get("caption")
        if caption is not None and not isinstance(caption, str):
            raise HTTPException(status_code=400, detail="caption must be a string or null")
        updates.append("caption = %s")
        params.append(caption)

    if "section" in payload:
        section = payload.get("section")
        if section is not None and not isinstance(section, str):
            raise HTTPException(status_code=400, detail="section must be a string or null")
        updates.append("section = %s")
        params.append(section)

    if "sort_order" in payload:
        sort_order = payload.get("sort_order")
        if not isinstance(sort_order, (int, float)):
            raise HTTPException(status_code=400, detail="sort_order must be a number")
        updates.append("sort_order = %s")
        params.append(int(sort_order))

    # FIX521.2.1.1.5 / <item-main-img>: per-row Main checkbox.
    # FIX521.5.6: at most one folder_image per folder may have is_main=true,
    # so when this row is set to true we clear the flag on every sibling
    # in the same folder atomically.
    set_is_main_true = False
    if "is_main" in payload:
        is_main = payload.get("is_main")
        if not isinstance(is_main, bool):
            raise HTTPException(status_code=400, detail="is_main must be a boolean")
        updates.append("is_main = %s")
        params.append(is_main)
        set_is_main_true = is_main

    if not updates:
        raise HTTPException(status_code=400, detail="nothing to update")

    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select id, folder_id from folder_image where id = %s",
                (folder_image_id,),
            )
            existing = cur.fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="folder_image not found")
            if set_is_main_true:
                cur.execute(
                    "update folder_image set is_main = false "
                    "where folder_id = %s and id <> %s and is_main = true",
                    (existing["folder_id"], folder_image_id),
                )
            cur.execute(
                f"update folder_image set {', '.join(updates)} where id = %s "
                "returning id, caption, section, sort_order, is_main",
                (*params, folder_image_id),
            )
            row = cur.fetchone()
        conn.commit()
    return {
        "id": row["id"],
        "caption": row["caption"],
        "section": row["section"],
        "sort_order": row["sort_order"],
        "is_main": row["is_main"],
    }


# FIX521.2.1.4: remove an image from an item. Deletes the folder_image
# row, and when no other folder_image references the same image_id, also
# deletes the image row + the bucket object so storage doesn't leak.
@app.delete("/api/folder-images/{folder_image_id}")
async def delete_folder_image(
    folder_image_id: int,
    user=Depends(current_user_required),
):
    storage_key_to_drop = None
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select image_id from folder_image where id = %s",
                (folder_image_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="folder_image not found")
            image_id = row["image_id"]
            cur.execute("delete from folder_image where id = %s", (folder_image_id,))
            # Any other folder_image still pointing at this image?
            cur.execute(
                "select 1 from folder_image where image_id = %s limit 1",
                (image_id,),
            )
            still_used = cur.fetchone() is not None
            if not still_used:
                cur.execute(
                    "select storage_key from image where id = %s",
                    (image_id,),
                )
                img = cur.fetchone()
                if img:
                    storage_key_to_drop = img["storage_key"]
                    cur.execute("delete from image where id = %s", (image_id,))
        conn.commit()
    # Drop the bucket object after the DB commit so a transient bucket
    # error doesn't roll back the user-facing remove. Any bucket failure
    # leaves an orphan that can be cleaned later — never a half-removed
    # row visible to the UI.
    if storage_key_to_drop:
        try:
            _bucket_delete(storage_key_to_drop)
        except HTTPException as e:
            print(f"delete_folder_image: bucket cleanup failed for {storage_key_to_drop}: {e.detail}", flush=True)
    return {"deleted": True, "image_deleted": storage_key_to_drop is not None}


# FIX520.2.10 (Showcase image viewer toolbox) non-destructive save: update
# crop rectangle and/or rotation on the Image row. The physical asset in
# the bucket is never touched — the viewer composes the final pixels at
# render time from storage_key + rotation + crop.
@app.patch("/api/images/{image_id}")
async def update_image(
    image_id: int,
    request: Request,
    user=Depends(current_user_required),
):
    payload = await request.json()
    updates: list[str] = []
    params: list = []

    if "rotation" in payload:
        rot = payload.get("rotation")
        if rot is not None and not isinstance(rot, (int, float)):
            raise HTTPException(status_code=400, detail="rotation must be a number")
        updates.append("rotation = %s")
        # Normalise to [0, 360) so downstream renders get a consistent value.
        params.append(int(rot) % 360 if rot is not None else 0)

    if "crop" in payload:
        crop = payload.get("crop")
        if crop is not None:
            if not isinstance(crop, dict):
                raise HTTPException(status_code=400, detail="crop must be an object or null")
            for k in ("x", "y", "width", "height"):
                if k not in crop or not isinstance(crop[k], (int, float)):
                    raise HTTPException(
                        status_code=400,
                        detail=f"crop.{k} (number) is required when crop is provided",
                    )
        updates.append("crop = %s::jsonb")
        params.append(json.dumps(crop) if crop is not None else None)

    if not updates:
        raise HTTPException(status_code=400, detail="nothing to update")

    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select id from image where id = %s", (image_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="image not found")
            cur.execute(
                f"update image set {', '.join(updates)} where id = %s "
                "returning id, rotation, crop",
                (*params, image_id),
            )
            row = cur.fetchone()
        conn.commit()
    return {
        "id": row["id"],
        "rotation": row["rotation"],
        "crop": row["crop"],
    }
