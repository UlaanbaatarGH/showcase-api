import os
import json
import time
import base64
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

pool = ConnectionPool(conninfo=DATABASE_URL, min_size=1, max_size=5, open=False)

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
                    "select id, name, cover_image_key, is_public "
                    "from project where is_public "
                    "order by name, id"
                )
            else:
                cur.execute(
                    "select distinct p.id, p.name, p.cover_image_key, p.is_public "
                    "from project p "
                    "left join project_access pa "
                    "       on pa.project_id = p.id and pa.user_id = %s "
                    "where p.is_public "
                    "   or pa.user_id is not null "
                    "   or p.owner_id = %s "
                    "order by p.name, p.id",
                    (user["id"], user["id"]),
                )
            rows = cur.fetchall()
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "is_public": r["is_public"],
            "cover_image_url": (
                public_image_url(r["cover_image_key"]) if r["cover_image_key"] else None
            ),
        }
        for r in rows
    ]


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
                "select p.id, p.label, p.sort_order "
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
                  img.rotation    as main_rotation
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

            for idx, p in enumerate(incoming_props):
                label = (p.get("label") or "").strip()
                if not label:
                    continue
                sort_order = p.get("sort_order", idx)
                if isinstance(p.get("id"), int) and p["id"] in existing_ids:
                    cur.execute(
                        "update property set label = %s, sort_order = %s where id = %s",
                        (label, sort_order, p["id"]),
                    )
                else:
                    cur.execute(
                        "insert into property (master_folder_id, label, sort_order) "
                        "values (%s, %s, %s) returning id",
                        (master_folder_id, label, sort_order),
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
                "select id, label, sort_order from property "
                "where master_folder_id = %s order by sort_order, id",
                (master_folder_id,),
            )
            fresh_properties = cur.fetchall()
        conn.commit()
    return {"properties": fresh_properties, "view_setup": view_setup}


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
                  fi.is_main,
                  fi.sort_order,
                  img.storage_key,
                  img.rotation
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
            "caption": r["caption"],
            "is_main": r["is_main"],
            "sort_order": r["sort_order"],
            "url": public_image_url(r["storage_key"]),
            "rotation": r["rotation"],
        }
        for r in rows
    ]
