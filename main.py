import os
import json
from contextlib import contextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]
SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SUPABASE_BUCKET = os.environ.get("SUPABASE_BUCKET", "showcase-images")
ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,https://showcase.x22.fr,https://showcase-omega-jade.vercel.app",
).split(",")


def public_image_url(storage_key: str) -> str:
    return f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_BUCKET}/{storage_key}"

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
            cur.execute(
                "select id, label, sort_order from property "
                "where project_id = %s order by sort_order, id",
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

            cur.execute(
                "select id from property where project_id = %s",
                (project_id,),
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
                        "insert into property (project_id, label, sort_order) "
                        "values (%s, %s, %s) returning id",
                        (project_id, label, sort_order),
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
                "where project_id = %s order by sort_order, id",
                (project_id,),
            )
            fresh_properties = cur.fetchall()
        conn.commit()
    return {"properties": fresh_properties, "view_setup": view_setup}


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
