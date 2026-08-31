import os
import json
import re
import html
import time
import base64
import hashlib
import hmac
import secrets
import traceback
import mimetypes
import unicodedata
import io
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Optional
import urllib.request
import urllib.error
import urllib.parse
import boto3
from botocore.config import Config
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

# TECH: local-app trust bypass. Only ever set in backend-dev/.env, never in
# the deployed (Render) config. FIX650: the local app drops the login
# requirement entirely, so an unauthenticated request against this backend
# is treated as the trusted local admin instead of anonymous.
LOCAL_APP = os.environ.get("LOCAL_APP") == "1"
LOCAL_APP_USER_ID = "cff25e93-75f6-4dc7-950a-7a53ddd7d813"  # Herve, app_user.is_admin=true

# FIX405.4.2 <sign-in-possible-attempts>: consecutive failed sign-ins
# allowed before <user-is-locked-out> (FIX310.12) flips true.
SIGN_IN_POSSIBLE_ATTEMPTS = 3

# Cloudflare R2 (S3-compatible) — image object storage. The database and auth
# stay in Supabase; only image FILES live in R2. Public reads come from
# R2_PUBLIC_BASE (the bucket's r2.dev URL or a custom domain).
R2_ENDPOINT = os.environ.get("R2_ENDPOINT")  # https://<account>.r2.cloudflarestorage.com
R2_BUCKET = os.environ.get("R2_BUCKET", "showcase-images")
R2_ACCESS_KEY_ID = os.environ.get("R2_ACCESS_KEY_ID")
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY")
R2_PUBLIC_BASE = os.environ.get("R2_PUBLIC_BASE", "").rstrip("/")  # https://pub-xxxx.r2.dev
# pub-*.r2.dev is Cloudflare-cached with no purge control available to this
# app (the R2 API token is object-scoped only, confirmed AccessDenied on
# both get/put_bucket_cors). Some objects got cached at some edge PoPs
# before the bucket's CORS policy was set, without the Access-Control-
# Allow-Origin header the canvas viewer's crossOrigin loads require (plain
# <img> loads are unaffected, which is why some views showed an image the
# canvas viewer couldn't). Bumping this forces every image URL to a new
# cache key app-wide, one line, no per-callsite frontend changes to miss —
# self-service recovery if this recurs: bump R2_CACHE_BUST in Render's env,
# no code deploy needed.
R2_CACHE_BUST = os.environ.get("R2_CACHE_BUST", "1")

_s3_client = None


def s3():
    """Lazily-built S3 client pointed at R2. Raises 503 if R2 isn't configured."""
    global _s3_client
    if _s3_client is None:
        if not (R2_ENDPOINT and R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY):
            raise HTTPException(status_code=503, detail="R2 storage not configured")
        _s3_client = boto3.client(
            "s3",
            endpoint_url=R2_ENDPOINT,
            aws_access_key_id=R2_ACCESS_KEY_ID,
            aws_secret_access_key=R2_SECRET_ACCESS_KEY,
            region_name="auto",
            config=Config(
                signature_version="s3v4",
                connect_timeout=5,
                read_timeout=15,
                retries={"max_attempts": 2},
            ),
        )
    return _s3_client


ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,https://showcase.x22.fr,https://showcase-omega-jade.vercel.app",
).split(",")


# TECH bug fix: same class of bug as thumbnail_url's cb -- the static
# global R2_CACHE_BUST token means every full-image URL is identical
# forever, so if R2's CORS policy (or any other origin-response detail)
# ever changed AFTER a given image was first fetched, edges that already
# cached the old response under the "immutable, max-age=1y" header keep
# serving it -- including a stale response with no Access-Control-Allow-
# Origin header, which the browser reports as a CORS error even though
# the object itself is fine (confirmed live: a direct HTTP GET/HEAD with
# Origin set returns a proper CORS header today). A caller with the
# image's own created_at gets a URL that's never been cached anywhere,
# sidestepping the whole class of staleness.
def public_image_url(storage_key: str, created_at=None) -> str:
    if created_at is not None:
        return f"{R2_PUBLIC_BASE}/{storage_key}?cb={int(created_at.timestamp())}"
    return f"{R2_PUBLIC_BASE}/{storage_key}?cb={R2_CACHE_BUST}"


# FIX371.6.2.1 / FIX670.20.4: 400x400 centre-cropped JPEG q80, stored
# alongside the original under its own key -- always .jpg regardless of the
# original's format, since the thumbnail format is fixed by spec.
def thumbnail_storage_key(storage_key: str) -> str:
    base = storage_key.rsplit(".", 1)[0] if "." in storage_key.rsplit("/", 1)[-1] else storage_key
    return f"{base}_thumb.jpg"


# TECH: cb defaults to the global R2_CACHE_BUST token, but a caller with a
# per-image thumb_created_at should pass it instead -- the object is
# regenerated in place under the same key (rotation-fix backfills,
# replace-bytes), and the global token doesn't change on that, so R2's
# public-domain "immutable, max-age=1y" header keeps every edge/browser
# cache pinned to the stale bytes at that URL until the URL itself changes.
def thumbnail_url(storage_key: str, thumb_created_at=None) -> str:
    if thumb_created_at is not None:
        return f"{R2_PUBLIC_BASE}/{thumbnail_storage_key(storage_key)}?cb={int(thumb_created_at.timestamp())}"
    return public_image_url(thumbnail_storage_key(storage_key))


def _create_thumbnail(storage_key: str) -> None:
    """FIX371.6.2.1 / FIX670.20.4: read the just-uploaded original back from
    R2, centre-crop to a 400x400 JPEG (quality 80), upload it under
    thumbnail_storage_key(storage_key). Best-effort -- called from
    confirm_image, where a thumbnail failure must not fail the image
    upload itself (the gallery falls back to the full image, FIX511.4.1)."""
    from PIL import Image, ImageOps  # lazy: optional dependency, same pattern as _image_dims_from_url
    obj = s3().get_object(Bucket=R2_BUCKET, Key=storage_key)
    data = obj["Body"].read()
    with Image.open(io.BytesIO(data)) as im:
        # Bug fix: PIL reads raw pixel data and ignores the EXIF Orientation
        # tag phone/camera photos are commonly saved with -- browsers
        # auto-rotate the original for display, but a thumbnail built
        # straight from im.crop()/resize() came out rotated relative to
        # that. exif_transpose() physically applies the tag's rotation/flip
        # once here and drops it, so the saved JPEG needs no tag at all.
        im = ImageOps.exif_transpose(im)
        im = im.convert("RGB")
        w, h = im.size
        side = min(w, h)
        left, top = (w - side) // 2, (h - side) // 2
        im = im.crop((left, top, left + side, top + side)).resize((400, 400), Image.LANCZOS)
        buf = io.BytesIO()
        im.save(buf, format="JPEG", quality=80)
    upload_to_bucket(thumbnail_storage_key(storage_key), buf.getvalue(), "image/jpeg")


def upload_to_bucket(storage_key: str, data: bytes, content_type: str) -> None:
    try:
        s3().put_object(
            Bucket=R2_BUCKET,
            Key=storage_key,
            Body=data,
            ContentType=content_type or "application/octet-stream",
            CacheControl="public, max-age=31536000, immutable",
        )
    except HTTPException:
        raise
    except Exception as e:
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

# FIX521.5.7.1: Reference Viewport (hardcoded; matches src/zoom.js).
REF_VIEWPORT_W, REF_VIEWPORT_H = 1920, 911


def _image_dims_from_url(url):
    """Read an image's pixel size. Tries a header-sized range first to avoid
    downloading whole images, falling back to the full object. Returns (w, h)
    or None. Pillow is imported lazily so a missing dep can't break startup."""
    from PIL import Image  # lazy: optional dependency, only needed for backfill
    for byte_range in (262144, None):
        try:
            headers = {"User-Agent": "showcase-zoom-backfill"}
            if byte_range:
                headers["Range"] = f"bytes=0-{byte_range - 1}"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            with Image.open(io.BytesIO(data)) as im:
                return im.width, im.height
        except Exception:
            continue
    return None


def _backfill_zoom_factors():
    """FIX521.5.8.1 backfill: populate stored Zoom Factors that are still NULL.

    (1) <img-zoom-factor>: for each image with no stored ZF, read its pixel
        dimensions and store image.zoom_factor = max(W/RVw, H/RVh).
    (2) <item-img-zoom-factor>: for each item (folder) with no stored ZF, set
        folder.zoom_factor to the max of its images' now-stored ZF.

    Runs in a background thread on startup; self-limits to NULL rows so it
    converges over reboots and is safe to re-run (idempotent migration)."""
    try:
        # (1) per-image ZF — the data migration over all images missing it.
        with pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("select id, storage_key from image where zoom_factor is null")
                imgs = cur.fetchall()
        if imgs:
            print(f"[backfill-zoom] measuring {len(imgs)} images")
        measured = 0
        for r in imgs:
            dims = _image_dims_from_url(public_image_url(r["storage_key"]))
            if not dims:
                continue
            w, h = dims
            zf = max(w / REF_VIEWPORT_W, h / REF_VIEWPORT_H)
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "update image set zoom_factor = %s where id = %s and zoom_factor is null",
                        (zf, r["id"]),
                    )
                conn.commit()
            measured += 1
        # (2) per-item max ZF, derived from the stored per-image ZF (no extra
        #     downloads). Only fills folders that don't have one yet.
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    update folder f
                       set zoom_factor = sub.max_zf
                      from (
                            select fi.folder_id, max(i.zoom_factor) as max_zf
                              from folder_image fi
                              join image i on i.id = fi.image_id
                             group by fi.folder_id
                           ) sub
                     where f.id = sub.folder_id
                       and f.zoom_factor is null
                       and sub.max_zf is not null
                    """
                )
            conn.commit()
        if imgs:
            print(f"[backfill-zoom] done ({measured}/{len(imgs)} images measured)")
    except Exception as e:  # pragma: no cover - log and continue
        print(f"[backfill-zoom] failed: {e}")


def _backfill_thumbnails():
    """FIX371.6.2.1 / FIX670.20.4 backfill: generate the 400x400 thumbnail
    for every image that predates those FIX items (thumb_created_at still
    NULL) -- same converges-over-reboots shape as _backfill_zoom_factors,
    and a per-image failure (missing/unreadable original) just leaves that
    one row NULL for next time rather than aborting the batch."""
    try:
        with pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("select id, storage_key from image where thumb_created_at is null")
                imgs = cur.fetchall()
        if imgs:
            print(f"[backfill-thumb] generating {len(imgs)} thumbnails")
        done = 0
        for r in imgs:
            try:
                _create_thumbnail(r["storage_key"])
            except Exception as e:
                print(f"[backfill-thumb] failed key={r['storage_key']}: {e}")
                continue
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "update image set thumb_created_at = now() where id = %s",
                        (r["id"],),
                    )
                conn.commit()
            done += 1
        if imgs:
            print(f"[backfill-thumb] done ({done}/{len(imgs)} images)")
    except Exception as e:  # pragma: no cover - log and continue
        print(f"[backfill-thumb] failed: {e}")


@app.on_event("startup")
def on_startup():
    pool.open()
    # FIX521.5.8.0 <item-img-zoom-factor>: stored per-item Zoom Factor.
    # FIX521.5.8.1 <img-zoom-factor>: stored per-image Zoom Factor.
    # Idempotent so it's safe to run on every boot.
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("alter table folder add column if not exists zoom_factor double precision")
                cur.execute("alter table image add column if not exists zoom_factor double precision")
            conn.commit()
    except Exception as e:  # pragma: no cover - log and continue
        print(f"[schema] zoom_factor ensure failed: {e}")
    # FIX521.5.8.0 / FIX521.5.8.1: backfill stored Zoom Factors in the
    # background so boot isn't blocked. Self-limits to NULL-zoom items.
    threading.Thread(target=_backfill_zoom_factors, daemon=True).start()
    # FIX371.6.2.1 / FIX670.20.4: thumb_created_at tracks which images
    # already have a thumbnail, so the backfill below (and every future
    # boot) only touches the ones that don't -- without it, "does this
    # image have a thumbnail" would mean a live R2 HEAD per image, every
    # single restart, forever.
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("alter table image add column if not exists thumb_created_at timestamptz")
            conn.commit()
    except Exception as e:  # pragma: no cover - log and continue
        print(f"[schema] thumb_created_at ensure failed: {e}")
    threading.Thread(target=_backfill_thumbnails, daemon=True).start()


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
# FIX310: auth helpers (Supabase JWT verification)
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
    """Returns {id, email} if a valid bearer token is present, None otherwise.
    FIX650 / TECH (LOCAL_APP): with no bearer token, a local-app deployment
    resolves to the trusted local admin instead of anonymous — the local
    app has no sign-in flow."""
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        if LOCAL_APP:
            return {"id": LOCAL_APP_USER_ID, "email": "herve@showcase.app"}
        return None
    user = _verify_token(auth.split(" ", 1)[1].strip())
    return {"id": user.get("id"), "email": user.get("email")}


def current_user_required(request: Request) -> dict:
    user = current_user_optional(request)
    if not user:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


# FIX311 / FIX410: admin endpoints require is_admin = true on
# app_user, on top of a valid Supabase token.
def current_admin_required(request: Request) -> dict:
    user = current_user_required(request)
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select is_admin from app_user where id = %s", (user["id"],))
            row = cur.fetchone()
    if not row or not row["is_admin"]:
        raise HTTPException(status_code=403, detail="admin access required")
    return user


# ============================================================
# FIX310[deep-updated from FIX310(deep-old)]: users, id <record-user>.
# Fields: <user-username> (.1), <user-password> (.2), <user-access-code>
# (.3), <user-email> (.4), <user-is-admin> (.10), the per-project access
# list (.11), <user-is-locked-out> (.12, FIX405.4's lockout flag).
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
                "returning id, login_name, is_admin, created_at",
                (user["id"], login_name),
            )
            row = cur.fetchone()
            row["managed_project_ids"] = _managed_project_ids(cur, user["id"])
            row["user_managed_project_ids"] = _user_managed_project_ids(cur, user["id"])
        conn.commit()
    # FIX410.1.1.6.2: "no one can ... login, admin excepted". Reusing 401
    # here (rather than 403) piggybacks on the existing stale-token
    # recovery path both frontend call sites already have -- it clears
    # the token and signs the user back out with no extra client code.
    if not row["is_admin"] and _maintenance_enabled():
        raise HTTPException(status_code=401, detail="site is in maintenance")
    return row


def _managed_project_ids(cur, user_id) -> list:
    # FIX311.5.6 / FIX351.2.x: list of project ids the caller has a
    # project_access row for, regardless of role. Used by the header
    # gating (admin-or-manager) and the FIX351.5.7 enable rule for
    # <button-edit-project>.
    cur.execute(
        "select project_id from project_access where user_id = %s",
        (user_id,),
    )
    return [r["project_id"] for r in cur.fetchall()]


def _user_managed_project_ids(cur, user_id) -> list:
    # FIX312.4.2: User Managers (project_access rows with
    # is_user_manager=true) are the ones allowed to assign or
    # unassign their project to other users.
    cur.execute(
        "select project_id from project_access "
        "where user_id = %s and is_user_manager",
        (user_id,),
    )
    return [r["project_id"] for r in cur.fetchall()]


@app.get("/api/users/me")
def get_me(user=Depends(current_user_required)):
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                # FIX420.4.2.5: surface the user's email so the Contact
                # panel can pre-fill <msg-reply-addr> when signed in.
                "select id, login_name, email, is_admin, created_at "
                "from app_user where id = %s",
                (user["id"],),
            )
            row = cur.fetchone()
            if row is not None:
                row["managed_project_ids"] = _managed_project_ids(cur, user["id"])
                row["user_managed_project_ids"] = _user_managed_project_ids(
                    cur, user["id"],
                )
    if not row:
        raise HTTPException(status_code=404, detail="user row not created yet")
    return row


# ============================================================
# FIX410.1.1.1.1: log each consultation of <panel-app-home> /
# <panel-project-home>. Anonymous and signed-in alike. The frontend
# fires this from the page-mount effect.
# FIX410.1.1.1.1.1: only "home" and "project" are valid pages — anything
# else is rejected to keep the log scoped to what the panel displays.
# ============================================================
def _client_ip(request: Request) -> Optional[str]:
    # Behind Vercel's edge rewrite, the original client IP is in
    # X-Forwarded-For (first entry) or X-Real-IP. Fall back to the direct
    # connection so local dev still records something.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.headers.get("x-real-ip") or (request.client.host if request.client else None)


@app.post("/api/track")
async def track_visit(request: Request, user=Depends(current_user_optional)):
    payload = await request.json() if await request.body() else {}
    page = (payload.get("page") or "").strip()
    # FIX412.5.1.2: 'login_ok' / 'login_failed' replace the old single
    # 'login' tag — the page value itself encodes whether the attempt
    # succeeded. 'login' kept accepted for backward compatibility with
    # rows from an older client.
    valid_pages = ("home", "project", "login_ok", "login_failed", "login")
    if page not in valid_pages:
        raise HTTPException(
            status_code=400,
            detail=f"page must be one of {valid_pages}",
        )
    ip = _client_ip(request)
    user_id = user["id"] if user else None
    # FIX412.5.1.1: store the name the user typed at sign-in so the
    # User column can display it even when the attempt failed (and
    # therefore has no app_user join). Only meaningful for login rows.
    typed_login = (payload.get("login_name") or "").strip() or None
    # FIX412.2.1.1.1: 'project' visits carry the project id so the
    # Page column can render the project's name. Ignored for other
    # page types.
    project_id = payload.get("project_id") if page == "project" else None
    if project_id is not None:
        try:
            project_id = int(project_id)
        except (TypeError, ValueError):
            project_id = None
    # FIX412.5.1: every sign-in attempt is recorded, no dedup — failed
    # then succeeded within seconds is a legitimate sequence the admin
    # needs to see distinctly. For 'home' / 'project' page hits, keep
    # the soft 30s dedup on (ip, page, user_id, project_id) so a
    # refresh / React StrictMode double-mount doesn't double-log, but
    # a sign-in inside the same window still produces a fresh row.
    # FIX405.4: 'login_failed' / 'login_ok' also drive the per-user
    # lockout counter (FIX310.12 <user-is-locked-out>) so the frontend
    # can render FIX405.4.1.1 / .4.1.2's messages off this same call.
    lockout = None
    try:
        with pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                if page.startswith("login"):
                    cur.execute(
                        "insert into visit (user_id, ip, page, typed_login) "
                        "values (%s, %s, %s, %s)",
                        (user_id, ip, page, typed_login),
                    )
                else:
                    cur.execute(
                        "insert into visit (user_id, ip, page, project_id) "
                        "select %s, %s, %s, %s "
                        "where not exists ("
                        "  select 1 from visit "
                        "  where ip is not distinct from %s "
                        "    and page = %s "
                        "    and user_id is not distinct from %s "
                        "    and project_id is not distinct from %s "
                        "    and ts > now() - interval '30 seconds'"
                        ")",
                        (user_id, ip, page, project_id, ip, page, user_id, project_id),
                    )
                if page == "login_failed" and typed_login:
                    cur.execute(
                        "update app_user set failed_signin_attempts = failed_signin_attempts + 1 "
                        "where lower(login_name) = lower(%s) "
                        "returning failed_signin_attempts",
                        (typed_login,),
                    )
                    row = cur.fetchone()
                    if row:
                        attempts = row["failed_signin_attempts"]
                        locked_out = attempts >= SIGN_IN_POSSIBLE_ATTEMPTS
                        if locked_out:
                            cur.execute(
                                "update app_user set is_locked_out = true "
                                "where lower(login_name) = lower(%s)",
                                (typed_login,),
                            )
                        lockout = {
                            "locked_out": locked_out,
                            "attempts_remaining": max(SIGN_IN_POSSIBLE_ATTEMPTS - attempts, 0),
                        }
                    else:
                        # FIX405.4.1.1: unknown login name — nothing to
                        # persist, but answer with the same shape a
                        # fresh real account would get so this can't be
                        # used to tell a typo from a real name.
                        lockout = {
                            "locked_out": False,
                            "attempts_remaining": SIGN_IN_POSSIBLE_ATTEMPTS - 1,
                        }
                elif page == "login_ok" and user_id:
                    cur.execute(
                        "update app_user set failed_signin_attempts = 0 where id = %s",
                        (user_id,),
                    )
            conn.commit()
    except Exception:
        traceback.print_exc()
    return {"ok": True, **({"lockout": lockout} if lockout is not None else {})}


@app.get("/api/admin/visits")
def list_visits(_user=Depends(current_user_required)):
    # FIX412.2.1.1.1: include the project's name when the visit row
    # is tagged with project_id so the History tab can render
    # '{project-name}' in the Page column.
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select u.login_name, v.ip, v.page, v.ts, v.typed_login, "
                "       p.name as project_name "
                "from visit v "
                "left join app_user u on u.id = v.user_id "
                "left join project  p on p.id = v.project_id "
                "order by v.ts desc "
                "limit 200"
            )
            rows = cur.fetchall()
    return [
        {
            "login_name": r["login_name"],
            "ip": r["ip"],
            "page": r["page"],
            "ts": r["ts"].isoformat(),
            "typed_login": r["typed_login"],
            "project_name": r["project_name"],
        }
        for r in rows
    ]


# ============================================================
# FIX413: per-IP friendly name + per-page consultation counts.
# Single project today (FIX413.2.1.4 "{project-name1}"), so all
# page='project' visits roll up under the first project; multi-project
# aggregation will need page-level project_id tagging.
# ============================================================
@app.get("/api/admin/ip-stats")
def get_ip_stats(_user=Depends(current_user_required)):
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select id, name from project order by id")
            projects = cur.fetchall()
            cur.execute(
                "select v.ip, "
                "       coalesce(n.name, '') as name, "
                "       sum(case when v.page = 'home' then 1 else 0 end) as home_count, "
                "       sum(case when v.page = 'project' then 1 else 0 end) as project_count, "
                "       sum(case when v.page like 'login%' then 1 else 0 end) as login_count, "
                "       max(v.ts) as last_ts "
                "from visit v "
                "left join ip_name n on n.ip = v.ip "
                "where v.ip is not null "
                "group by v.ip, n.name "
                "order by max(v.ts) desc"
            )
            rows = cur.fetchall()
    return {
        "projects": [{"id": p["id"], "name": p["name"]} for p in projects],
        "rows": [
            {
                "ip": r["ip"],
                "name": r["name"],
                "home_count": int(r["home_count"] or 0),
                "project_count": int(r["project_count"] or 0),
                "login_count": int(r["login_count"] or 0),
                # FIX413.2.1.6 <ip-action-when>: timestamp of the IP's
                # most recent tracked action — login, home or project
                # visit. The SQL already orders rows by this descending
                # (FIX413.5.1).
                "last_ts": r["last_ts"].isoformat() if r["last_ts"] else None,
            }
            for r in rows
        ],
    }


# ============================================================
# FIX311 <panel-users>: admin-only user management. Lists all
# app_user rows with their flags + project-access summary, lets
# the admin add (FIX311.3.1) or remove (FIX311.3.2) users.
# ============================================================
def _user_row_to_dict(row, projects, see_sensitive=True):
    # FIX311.2.1.6 <user-projects>: projects is a list of {id, name}
    # so the frontend can target rows by id when editing the column
    # (FIX311.3.3) and not just display the names.
    # FIX311.5.9: <user-email> and <user-access-code> are masked when
    # the caller may not see them (PM with no shared project, etc.) —
    # defence-in-depth on top of the UI gate.
    return {
        "id": str(row["id"]),
        "name": row["login_name"],
        "email": row["email"] if see_sensitive else None,
        "access_code": row["access_code"] if see_sensitive else None,
        "is_admin": bool(row["is_admin"]),
        "has_password": bool(row.get("has_password")),
        # FIX310.12 / FIX311.2.1.7 <user-is-locked-out>: not gated by
        # FIX311.5.9 — unlike email/access-code it isn't listed there.
        "is_locked_out": bool(row.get("is_locked_out")),
        "projects": projects,
    }


@app.get("/api/admin/users")
def list_users(user=Depends(current_user_required)):
    # Per FIX311.5.{2..5}, only the editing affordances (add, remove,
    # rename, change email) are admin-only. The list itself is
    # visible to every signed-in user — they just see it read-only,
    # which the frontend enforces by hiding the toolbar.
    # FIX311.5.9: per-row gate on email + access_code — an admin sees
    # everything, a project manager sees them only for users that
    # have at least one project in common with the manager.
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select is_admin from app_user where id = %s", (user["id"],))
            pr = cur.fetchone()
            caller_is_admin = bool(pr and pr["is_admin"])
            cur.execute(
                "select project_id from project_access where user_id = %s",
                (user["id"],),
            )
            caller_managed = {r["project_id"] for r in cur.fetchall()}
            # FIX311.2.1.3.1: 'has_password' is true when the linked
            # Supabase auth.users row has an encrypted_password set.
            # Admin-created users without a Supabase Auth row stay
            # unchecked until they redeem their access code.
            cur.execute(
                "select u.id, u.login_name, u.email, u.access_code, u.is_admin, "
                "       u.is_locked_out, "
                "       (au.encrypted_password is not null) as has_password "
                "from app_user u "
                "left join auth.users au on au.id = u.id "
                "order by u.created_at"
            )
            users = cur.fetchall()
            cur.execute(
                "select pa.user_id, p.id, p.name "
                "from project_access pa "
                "join project p on p.id = pa.project_id "
                "order by p.sort_order, p.id"
            )
            access_rows = cur.fetchall()
    by_user = {}
    for r in access_rows:
        by_user.setdefault(str(r["user_id"]), []).append(
            {"id": r["id"], "name": r["name"]}
        )
    out = []
    for u in users:
        projects_for = by_user.get(str(u["id"]), [])
        if caller_is_admin:
            see_sensitive = True
        else:
            see_sensitive = any(p["id"] in caller_managed for p in projects_for)
        out.append(_user_row_to_dict(u, projects_for, see_sensitive))
    return out


@app.post("/api/admin/users")
async def create_user(request: Request, _admin=Depends(current_admin_required)):
    payload = await request.json() if await request.body() else {}
    name = (payload.get("name") or "").strip()
    email = (payload.get("email") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    if not email:
        raise HTTPException(status_code=400, detail="email required")
    # FIX311.3.1.1.3: 6-digit code, leading zeros preserved (text).
    # secrets.randbelow gives a crypto-strong choice — overkill but
    # cheap and avoids any predictability concerns.
    access_code = f"{secrets.randbelow(1000000):06d}"
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            # FIX311.3.1.1.1: name + email must be unique across users.
            # Case-insensitive: 'Herve' and 'herve' are the same handle.
            cur.execute(
                "select 1 from app_user where lower(login_name) = lower(%s)",
                (name,),
            )
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="name already in use")
            cur.execute(
                "select 1 from app_user where email = %s and email is not null",
                (email,),
            )
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="email already in use")
            # FIX311.3.1.1.2: is_admin defaults to false — never admin
            # via this flow. FIX311.3.1.1.4: project access stays empty.
            cur.execute(
                "insert into app_user (id, login_name, email, access_code) "
                "values (gen_random_uuid(), %s, %s, %s) "
                "returning id, login_name, email, access_code, is_admin",
                (name, email, access_code),
            )
            row = cur.fetchone()
        conn.commit()
    return _user_row_to_dict({**row, "has_password": False}, [])


# FIX317: helper that creates a Supabase auth.users row using the
# Service Role key. Used during account redemption — the caller is
# anonymous and trades a name + access code for a freshly-issued
# password.
def _supabase_admin_create_user(email: str, password: str) -> dict:
    if not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=503, detail="auth not configured")
    body = json.dumps({
        "email": email,
        "password": password,
        "email_confirm": True,
    }).encode()
    req = urllib.request.Request(
        f"{SUPABASE_URL}/auth/v1/admin/users",
        data=body,
        method="POST",
        headers={
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=400, detail=f"Supabase: {msg[:200]}")
    except urllib.error.URLError as e:
        raise HTTPException(status_code=502, detail=f"Supabase error: {e}")


# FIX318 <process-reset-pswd>: mirror of _supabase_admin_create_user
# for removal. Deleting the auth.users row makes has_password (joined
# off encrypted_password) false again -- the next redeem (FIX317)
# creates a fresh auth row and rewrites app_user.id, same as initial
# account creation. A 404 (nothing to delete -- the user never
# redeemed in the first place) is not an error here.
def _supabase_admin_delete_user(user_id: str) -> None:
    if not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=503, detail="auth not configured")
    req = urllib.request.Request(
        f"{SUPABASE_URL}/auth/v1/admin/users/{user_id}",
        method="DELETE",
        headers={
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        if e.code != 404:
            msg = e.read().decode("utf-8", errors="replace")
            raise HTTPException(status_code=400, detail=f"Supabase: {msg[:200]}")
    except urllib.error.URLError as e:
        raise HTTPException(status_code=502, detail=f"Supabase error: {e}")


# Bugfix (2026-08-23): a redemption/signup attempt can leave an orphaned
# Supabase auth.users row behind if the create call above succeeds but
# the local app_user update that follows it never commits (dropped
# connection, request cancelled, etc). A retry then hits email_exists
# on the *same* synthetic email even though nothing in Postgres was
# ever linked to it. These two helpers let the caller adopt that
# leftover row (reset its password, reuse its id) instead of getting
# stuck in a permanent email_exists loop.
def _supabase_admin_find_user_by_email(email: str) -> Optional[dict]:
    if not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=503, detail="auth not configured")
    qs = urllib.parse.urlencode({"filter": email})
    req = urllib.request.Request(
        f"{SUPABASE_URL}/auth/v1/admin/users?{qs}",
        method="GET",
        headers={
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=400, detail=f"Supabase: {msg[:200]}")
    except urllib.error.URLError as e:
        raise HTTPException(status_code=502, detail=f"Supabase error: {e}")
    users = data.get("users") if isinstance(data, dict) else data
    for u in users or []:
        if (u.get("email") or "").lower() == email.lower():
            return u
    return None


def _supabase_admin_set_password(user_id: str, password: str) -> None:
    if not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=503, detail="auth not configured")
    body = json.dumps({"password": password}).encode()
    req = urllib.request.Request(
        f"{SUPABASE_URL}/auth/v1/admin/users/{user_id}",
        data=body,
        method="PUT",
        headers={
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=400, detail=f"Supabase: {msg[:200]}")
    except urllib.error.URLError as e:
        raise HTTPException(status_code=502, detail=f"Supabase error: {e}")


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# FIX378.3.4.2: same sheet-id extraction as the frontend's
# gsheetImport.js parseGsheetUrl(), duplicated here (no shared module
# between the two runtimes) since this check has to run server-side --
# see the endpoint below for why.
_GSHEET_ID_RE = re.compile(r"/spreadsheets/d/([a-zA-Z0-9_-]+)")


@app.post("/api/gsheet-title")
async def gsheet_title(request: Request, _user=Depends(current_user_required)):
    """FIX378.3.4.2: fetch a Google Sheet's document title (not to be
    confused with a tab/sheet name) with no OAuth. The public CSV/gviz
    export endpoints FIX370's client-side import already fetches set
    permissive CORS, but the /edit page -- the only place the actual
    document title shows up (in its <title> tag) -- does not (confirmed:
    no access-control-allow-origin header), so a browser fetch() would
    be silently blocked. Server-to-server has no such restriction."""
    payload = await request.json() if await request.body() else {}
    url = (payload.get("url") or "").strip()
    m = _GSHEET_ID_RE.search(url)
    if not m:
        return {"title": None, "debug": "url did not match the spreadsheet id pattern"}
    req = urllib.request.Request(
        f"https://docs.google.com/spreadsheets/d/{m.group(1)}/edit",
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            page_html = resp.read().decode("utf-8", errors="replace")
            status = resp.status
    except urllib.error.HTTPError as e:
        # Debugging aid while this is new -- surfaces e.g. a 429/403 from
        # Google (suspected: datacenter-IP bot detection on the /edit page,
        # unlike the CSV/gviz export endpoints FIX370's import already
        # relies on) instead of silently reporting "nothing readable".
        print(f"[gsheet-title] HTTPError {e.code} fetching {url!r}", flush=True)
        return {"title": None, "debug": f"HTTP {e.code} from Google"}
    except Exception as e:
        print(f"[gsheet-title] {type(e).__name__}: {e} fetching {url!r}", flush=True)
        return {"title": None, "debug": f"{type(e).__name__}: {e}"}
    title_match = re.search(r"<title[^>]*>(.*?)</title>", page_html, re.IGNORECASE | re.DOTALL)
    if not title_match:
        print(
            f"[gsheet-title] no <title> tag, status={status} len={len(page_html)} "
            f"head={page_html[:200]!r}",
            flush=True,
        )
        return {"title": None, "debug": f"no title tag in response (HTTP {status}, {len(page_html)} bytes)"}
    # Google appends " - Google Sheets" to the raw document title, and
    # HTML-entity-encodes it (e.g. an '&' in the project name).
    raw_title = html.unescape(title_match.group(1).strip())
    title = re.sub(
        r"\s*-\s*Google Sheets\s*$", "", raw_title, flags=re.IGNORECASE,
    ).strip()
    return {"title": title or None}


# FIX420.3.1.3 transactional email — Resend is wired when this env
# var is set, otherwise the contact request is still recorded in
# the contact_message table and printed to the server log so admins
# can recover it manually. Recipient lives in the app_setting table
# (key='contact_to') per FIX420.3.1.3 — env var CONTACT_TO is kept
# as a fallback for local dev / pre-migration deployments.
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
RESEND_FROM = os.environ.get("RESEND_FROM", "onboarding@resend.dev")
# Optional acknowledgement-echo: when set (typically once the domain
# is verified in Resend), every contact submission also fires a
# no-reply confirmation back to the sender. Leaving it unset keeps
# the feature dormant — the admin email still goes out either way.
RESEND_NOREPLY_FROM = os.environ.get("RESEND_NOREPLY_FROM")
CONTACT_TO_FALLBACK = os.environ.get("CONTACT_TO")


def _resolve_contact_to() -> Optional[str]:
    """Read the configured recipient from app_setting.contact_to,
    falling back to the CONTACT_TO env var if the table or row is
    not present yet."""
    try:
        with pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "select value from app_setting where key = 'contact_to'"
                )
                row = cur.fetchone()
                if row and row["value"]:
                    return row["value"].strip()
    except Exception:
        traceback.print_exc()
    return CONTACT_TO_FALLBACK


# FIX410.1.1.6 <website-In-maintenance>: site-wide maintenance flag,
# stored the same way as contact_to (app_setting.maintenance_mode).
def _maintenance_enabled() -> bool:
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select value from app_setting where key = 'maintenance_mode'"
            )
            row = cur.fetchone()
    return bool(row and row["value"] == "true")


@app.get("/api/app-status")
def app_status():
    """Public (no auth) -- the home page needs this before knowing
    whether anyone is signed in, to show the FIX410.1.1.6.2 banner."""
    return {"in_maintenance": _maintenance_enabled()}


@app.patch("/api/admin/maintenance")
async def set_maintenance(request: Request, _admin=Depends(current_admin_required)):
    payload = await request.json()
    value = payload.get("in_maintenance")
    if not isinstance(value, bool):
        raise HTTPException(status_code=400, detail="in_maintenance must be a boolean")
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "insert into app_setting (key, value) values ('maintenance_mode', %s) "
                "on conflict (key) do update set value = excluded.value",
                ("true" if value else "false",),
            )
        conn.commit()
    return {"in_maintenance": value}


def _resend_send(payload: dict, *, label: str) -> Optional[dict]:
    """Internal Resend POST wrapper. Surfaces Resend's JSON error
    body in the log so the admin can diagnose without parsing a
    Python traceback. Returns the parsed JSON on success (with the
    'id' field carrying Resend's message id) or None on failure."""
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
            # Cloudflare in front of api.resend.com 403s (error 1010)
            # the default Python-urllib User-Agent. A neutral UA gets
            # the request through.
            "User-Agent": "showcase-api/1.0",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            parsed = json.loads(resp.read())
            print(f"[contact] {label} Resend response: {parsed!r}")
            return parsed
    except urllib.error.HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            pass
        print(
            f"[contact] {label} rejected by Resend: HTTP {e.code} "
            f"to={payload.get('to')!r} body={body_text!r}"
        )
    except Exception:
        traceback.print_exc()
    return None


def _ip_geolocation(ip: Optional[str]) -> Optional[str]:
    """FIX420.3.1.3.6: query ipapi.co for the sender's IP and return
    a concise human-readable string for the admin forward email
    (e.g. 'Paris, Île-de-France, France — Free SAS').
    Returns None on any error, on a private/loopback IP, or when no
    IP is available. The caller silently omits the section in that
    case so a slow / failing geo-lookup never blocks the email send."""
    if not ip:
        return None
    # Skip RFC1918 + loopback + link-local + IPv6 loopback. Public
    # ipapi.co would return 'Reserved Range' for these anyway.
    if (
        ip.startswith(("10.", "127.", "169.254.", "192.168."))
        or ip.startswith(tuple(f"172.{i}." for i in range(16, 32)))
        or ip == "::1"
    ):
        return None
    try:
        req = urllib.request.Request(
            f"https://ipapi.co/{ip}/json/",
            headers={"User-Agent": "showcase-api/1.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
    except Exception:
        return None
    if not isinstance(data, dict) or data.get("error"):
        return None
    parts = []
    for key in ("city", "region", "country_name"):
        v = data.get(key)
        if v:
            parts.append(str(v))
    location = ", ".join(parts) if parts else None
    isp = data.get("org") or None
    if location and isp:
        return f"{location} — {isp}"
    return location or isp


def _ip_short(ip: Optional[str]) -> str:
    """FIX420.3.1.3.10.1: when no logged-in user is available, the
    admin-email subject identifies the sender by the last two
    octets of their IPv4 address ('86.247.88.129' -> '88.129').
    Falls back to the full IP for IPv6 / unparseable inputs, or
    '(unknown)' when no IP at all."""
    if not ip:
        return "(unknown)"
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[2]}.{parts[3]}"
    return ip


# FIX509 / FIX422: server-side mirror of the frontend t() helper.
# Resolves a section-scoped i18n key against a language's labels
# JSONB, with placeholder substitution for any {placeholder} tokens
# the resolved text contains. Falls back to the key literal so the
# default English text is always returned even with no language data.
def _t(labels: Optional[dict], section: str, key: str,
       vars: Optional[dict] = None) -> str:
    text = key
    if isinstance(labels, dict):
        section_labels = labels.get(section)
        if isinstance(section_labels, dict):
            v = section_labels.get(key)
            if isinstance(v, str) and v:
                text = v
    if vars:
        for name, value in vars.items():
            text = text.replace("{" + name + "}", "" if value is None else str(value))
    return text


def _fetch_lang_labels(cur, lang_code: Optional[str]) -> Optional[dict]:
    """FIX509: pull the labels JSONB for a language code so the
    auto-reply (FIX422) can render in the visitor's chosen
    language. None when the code is missing / unknown — _t() then
    falls back to the key literals (English by convention)."""
    if not lang_code:
        return None
    cur.execute("select labels from language where code = %s", (lang_code,))
    row = cur.fetchone()
    if not row:
        return None
    return row["labels"] or {}


def _items_block(items: list[str], header: str) -> str:
    """Render a 'Selected items:' / 'Items you selected:' section
    used in both the admin forward and the sender echo. Empty
    string when there's nothing to list."""
    if not items:
        return ""
    bullets = "\n".join(f"  - {x}" for x in items)
    return f"{header}\n{bullets}\n\n"


def _send_contact_email(
    subject: str,
    message: str,
    sender_email: str,
    sender_ip: Optional[str] = None,
    sender_login: Optional[str] = None,
    items: Optional[list[str]] = None,
    project_name: Optional[str] = None,
    lang_labels: Optional[dict] = None,
) -> Optional[str]:
    """Best-effort Resend send. Failures are swallowed so a Resend
    outage doesn't drop the user's message — the row is already in
    contact_message and the admin can pick it up from there. Returns
    the echo message id when one was sent (used by /api/contact to
    store it on the row so a later bounce webhook can find it).

    FIX420.3.1.3 admin forward sections:
      .3.1 sender IP, .3.2 sender reply addr, .3.3 list of items,
      .3.4 subject + text.
    FIX420.4.2.{1,2} auto-reply: subject + body name the project and
    date/time. FIX420.4.2.2.1: also list the selected items the
    sender kept ticked."""
    items = items or []
    contact_to = _resolve_contact_to()
    if not RESEND_API_KEY or not contact_to:
        print(f"[contact] from={sender_email!r} subject={subject!r} body={message!r}")
        return None
    # FIX420.3.1.3.10 admin-email subject: '[<project>] <user-id> -- <msg-subject>'.
    # FIX420.3.1.3.10.1: <user-id> = login name when signed in, else
    # the last two octets of the IPv4 (88.129 for 86.247.88.129).
    user_id_str = sender_login or _ip_short(sender_ip)
    proj_label = project_name or "unknown"
    admin_subject = f"[{proj_label}] {user_id_str} -- {subject}"
    # FIX420.3.1.3.6 sender geolocation, best-effort.
    location = _ip_geolocation(sender_ip)
    location_line = f"Sender location: {location}\n" if location else ""
    # 1) FIX420.3.1.3 admin forward.
    admin_body = (
        # FIX420.3.1.3.1 sender IP.
        f"Sender IP: {sender_ip or '(unknown)'}\n"
        # FIX420.3.1.3.6 sender location (one line, omitted when the
        # geo-lookup failed or the IP is private).
        f"{location_line}"
        # FIX420.3.1.3.2 sender reply addr.
        f"Reply to: {sender_email}\n"
        "\n"
        # FIX420.3.1.3.3 selected items.
        f"{_items_block(items, 'Selected items:')}"
        # FIX420.3.1.3.4 subject + message text.
        f"Subject: {subject}\n"
        "\n"
        f"{message}\n"
    )
    _resend_send(
        {
            "from": RESEND_FROM,
            "to": [contact_to],
            "reply_to": sender_email,
            "subject": admin_subject,
            "text": admin_body,
        },
        label="admin forward",
    )
    # 2) Optional no-reply echo to the sender, gated on
    # RESEND_NOREPLY_FROM being configured (which presumes the
    # domain is verified in Resend so arbitrary recipients are
    # reachable). Until then this stays dormant.
    echo_id: Optional[str] = None
    if RESEND_NOREPLY_FROM:
        when = datetime.now().strftime("%a %d %b %Y / %H:%M")
        proj_label = project_name or "the project"
        # FIX422 i18n: resolve every translatable string in the
        # section '422. Automatic message reply' for the visitor's
        # chosen language. Falls back to the English key literal.
        SEC = "422. Automatic message reply"
        thanks = _t(lang_labels, SEC, "Thank you for your message")
        body_thanks = _t(
            lang_labels, SEC,
            'Thank you for your message about "{project-name}" on '
            '{date-time-ddd-dd-hh-mm}.',
            {"project-name": proj_label, "date-time-ddd-dd-hh-mm": when},
        )
        body_reply = _t(lang_labels, SEC, "We will reply soon.")
        body_disclaimer = _t(
            lang_labels, SEC,
            "(This is an automated acknowledgement; please do not "
            "reply to this address.)",
        )
        # FIX422.2.1 subject:
        #   'Showcase: {project-name} -- {Thank you for your message}'
        echo_subject = f"Showcase: {proj_label} -- {thanks}"
        # FIX422.2.2 body — three translated lines, then the
        # selected-items + original-message echo (kept from the
        # earlier FIX420.4.2.2.1 behaviour, English headers; if you
        # want those translated too just add the keys).
        echo_body = (
            f"{body_thanks}\n"
            "\n"
            f"{body_reply}\n"
            f"{body_disclaimer}\n"
            "\n"
            "----- Your message -----\n"
            f"{_items_block(items, 'Items you selected:')}"
            f"Subject: {subject}\n"
            "\n"
            f"{message}\n"
        )
        echo_resp = _resend_send(
            {
                "from": RESEND_NOREPLY_FROM,
                "to": [sender_email],
                "subject": echo_subject,
                "text": echo_body,
            },
            label="sender echo",
        )
        if echo_resp:
            mid = echo_resp.get("id")
            if isinstance(mid, str) and mid:
                echo_id = mid
    return echo_id


@app.post("/api/auth/redeem")
async def redeem_account(request: Request):
    """FIX317 (Manager flow) / FIX406: redeem an access code to set the
    user's password (and email, FIX406.2.5). Body: { name, access_code,
    password, email }. Caller is anonymous — after success the frontend
    calls supabase.auth.signInWithPassword with the same name + password
    to obtain a session."""
    payload = await request.json() if await request.body() else {}
    name = (payload.get("name") or "").strip()
    code = (payload.get("access_code") or "").strip()
    password = payload.get("password") or ""
    email = (payload.get("email") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    if not code:
        raise HTTPException(status_code=400, detail="access code required")
    # FIX317.3.1.3: password ≥ 8 chars (frontend also enforces this,
    # but the server is the source of truth).
    if len(password) < 8:
        raise HTTPException(
            status_code=400,
            detail="password must be at least 8 characters",
        )
    # FIX406.2.5: only shape-check email when one was actually sent —
    # it's optional here when <record-user> already has one (checked
    # against the row below).
    if email and not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="email is not valid")
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select u.id, u.login_name, u.access_code, u.email, "
                "       (au.encrypted_password is not null) as has_password "
                "from app_user u "
                "left join auth.users au on au.id = u.id "
                "where lower(u.login_name) = lower(%s)",
                (name,),
            )
            row = cur.fetchone()
            # FIX317.3.1.1 + .2: name exists, has_password is unchecked,
            # access code matches. Same generic error for all so a
            # caller can't tell which check failed.
            invalid = HTTPException(
                status_code=403,
                detail="invalid login name or access code",
            )
            if not row or row["has_password"]:
                raise invalid
            if row["access_code"] != code:
                raise invalid
            # FIX406.2.5: mandatory only when the record doesn't have
            # one yet — checked here (after the invalid-credential
            # checks above) so it never becomes an enumeration signal.
            if not row["email"] and not email:
                raise HTTPException(status_code=400, detail="email is not valid")
            final_email = email or row["email"]

            # Login flow stays login_name → <name>@showcase.app, so
            # use the synthetic email here too. Lowercased to match the
            # frontend's loginNameToEmail() (Supabase Auth normalises
            # to lowercase internally too — being explicit avoids any
            # surprise around what the auth row's email actually is).
            # The user's real email goes onto app_user.email below;
            # the Email column on the Users panel is administrative
            # metadata, not the auth identifier.
            synthetic_email = f"{name.lower()}@showcase.app"
            try:
                new_auth = _supabase_admin_create_user(synthetic_email, password)
            except HTTPException as create_err:
                # Bugfix (2026-08-23): the synthetic email is unique to
                # this login name, so email_exists here can only mean a
                # previous redemption attempt already created this auth
                # row but the app_user update below never ran (see the
                # helpers' docstring above). Adopt the leftover row
                # instead of failing forever.
                if "email_exists" not in (create_err.detail or ""):
                    raise
                existing = _supabase_admin_find_user_by_email(synthetic_email)
                if not existing:
                    raise
                _supabase_admin_set_password(existing["id"], password)
                new_auth = existing
            new_id = new_auth.get("id")
            if not new_id:
                raise HTTPException(
                    status_code=502,
                    detail="Supabase did not return a new user id",
                )
            # FIX317.3.1.10: rewrite app_user.id to match the new
            # Supabase auth id, store the user-entered email, clear
            # the access code. ON UPDATE CASCADE on the FKs keeps
            # project_access / visit linked.
            cur.execute(
                "update app_user set id = %s, email = %s, access_code = null "
                "where id = %s",
                (new_id, final_email, row["id"]),
            )
        conn.commit()
    return {"ok": True}


@app.get("/api/auth/signin-status")
def signin_status(name: str = ""):
    """FIX405.3.1 <process-sign-in> pre-check: is this login name
    currently locked out (FIX310.12 <user-is-locked-out>)? Anonymous —
    called before the frontend even attempts the Supabase credential
    check, so a locked account never reaches it. An unknown name reads
    as not-locked, same as a fresh account."""
    name = name.strip()
    locked_out = False
    if name:
        with pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "select is_locked_out from app_user where lower(login_name) = lower(%s)",
                    (name,),
                )
                row = cur.fetchone()
                locked_out = bool(row and row["is_locked_out"])
    return {"locked_out": locked_out}


@app.get("/api/auth/user-has-email")
def user_has_email(name: str = ""):
    """FIX406.2.5: does <record-user> for this login name already have
    an email on file? Drives whether <panel-sign-in-with access-code>
    shows its Email field. Only reveals a yes/no on that one fact — an
    unknown name and a known-but-emailless one both answer False."""
    name = name.strip()
    has_email = False
    if name:
        with pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "select email from app_user where lower(login_name) = lower(%s)",
                    (name,),
                )
                row = cur.fetchone()
                has_email = bool(row and row["email"])
    return {"has_email": has_email}


@app.post("/api/auth/signup-visitor")
async def signup_visitor(request: Request):
    """FIX316.2.1 (Visitor flow): self-signup for a lambda visitor
    account. No access code required. Body: { name, password, email }.
    Creates a fresh app_user row (non-admin, no project access) and the
    matching Supabase Auth row. The frontend signs in immediately
    after."""
    payload = await request.json() if await request.body() else {}
    name = (payload.get("name") or "").strip()
    password = payload.get("password") or ""
    email = (payload.get("email") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    if len(password) < 8:
        raise HTTPException(
            status_code=400,
            detail="password must be at least 8 characters",
        )
    if not email or not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="email is not valid")
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            # Login name and email both stay unique (case-insensitive
            # for name to match FIX315.5).
            cur.execute(
                "select 1 from app_user where lower(login_name) = lower(%s)",
                (name,),
            )
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="name already in use")
            cur.execute(
                "select 1 from app_user where email = %s and email is not null",
                (email,),
            )
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="email already in use")
            synthetic_email = f"{name.lower()}@showcase.app"
            new_auth = _supabase_admin_create_user(synthetic_email, password)
            new_id = new_auth.get("id")
            if not new_id:
                raise HTTPException(
                    status_code=502,
                    detail="Supabase did not return a new user id",
                )
            cur.execute(
                "insert into app_user (id, login_name, email) "
                "values (%s, %s, %s)",
                (new_id, name, email),
            )
        conn.commit()
    return {"ok": True}


# ============================================================
# FIX420 <panel-contact-admin>: anonymous Contact form. Stores the
# message in contact_message and forwards it to a configured admin
# inbox via Resend (FIX420.3.1.3). Rate-limited to once per minute
# per IP (FIX420.4.1).
# ============================================================
@app.post("/api/contact")
async def contact_admin(
    request: Request,
    user=Depends(current_user_optional),
):
    payload = await request.json() if await request.body() else {}
    subject = (payload.get("subject") or "").strip()
    message = (payload.get("message") or "").strip()
    email = (payload.get("email") or "").strip()
    # FIX420.4.2.4 <item-selection>: optional list of short labels for
    # the items the visitor had selected on the Showcase List and kept
    # ticked. Used by:
    # - FIX420.3.1.3.3 admin forward email (its own section).
    # - FIX420.4.2.2.1 sender echo email (its own section).
    # - <panel-message-list> body cell (prepended to the stored body
    #   so the admin sees the items in-context, no separate column).
    raw_items = payload.get("items")
    items: list[str] = []
    if isinstance(raw_items, list):
        items = [str(x).strip() for x in raw_items if str(x).strip()]
    stored_body = message
    if items:
        items_block = "Selected items:\n" + "\n".join(f"  - {x}" for x in items)
        stored_body = f"{items_block}\n\n{message}"
    # FIX422: visitor's chosen UI language code (e.g., 'fr'). The
    # auto-reply email is rendered in that language when one is
    # provided. None / unknown / 'en' all fall back to the key
    # literals (English by convention).
    lang_code = (payload.get("lang") or "").strip() or None
    # FIX421.2.1.2: tag the message with the project context it was
    # submitted from so <panel-message-list> can filter per project.
    project_id_raw = payload.get("project_id")
    project_id = None
    if project_id_raw is not None:
        try:
            project_id = int(project_id_raw)
        except (TypeError, ValueError):
            project_id = None
    # FIX420.3.1.1: every field non-blank.
    if not subject:
        raise HTTPException(status_code=400, detail="subject required")
    if not message:
        raise HTTPException(status_code=400, detail="message required")
    if not email:
        raise HTTPException(status_code=400, detail="email required")
    # FIX420.3.1.2: email shape check.
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="email is not valid")
    ip = _client_ip(request)
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            # FIX420.4.1: 1-minute cooldown per IP. Same generic 429
            # for any IP that posted recently.
            if ip is not None:
                cur.execute(
                    "select 1 from contact_message "
                    "where ip = %s and ts > now() - interval '60 seconds' "
                    "limit 1",
                    (ip,),
                )
                if cur.fetchone():
                    raise HTTPException(
                        status_code=429,
                        detail="please wait a minute before sending another message",
                    )
            cur.execute(
                "insert into contact_message "
                "(ip, subject, body, sender_email, project_id) "
                "values (%s, %s, %s, %s, %s) returning id",
                (ip, subject, stored_body, email, project_id),
            )
            row_id = cur.fetchone()["id"]
            # FIX420.4.2.2: fetch the project name so the echo can
            # include it in the subject and body.
            project_name: Optional[str] = None
            if project_id is not None:
                cur.execute(
                    "select name from project where id = %s",
                    (project_id,),
                )
                pr = cur.fetchone()
                if pr:
                    project_name = pr["name"]
            # FIX420.3.1.3.10.1: when the sender is signed in, use
            # their login_name in the admin-email subject. Falls back
            # to the IP-octet form when anonymous.
            sender_login: Optional[str] = None
            if user is not None:
                cur.execute(
                    "select login_name from app_user where id = %s",
                    (user["id"],),
                )
                row = cur.fetchone()
                if row:
                    sender_login = row["login_name"]
            # FIX422: pull the visitor language's labels JSONB so
            # the auto-reply renders in their language.
            lang_labels = _fetch_lang_labels(cur, lang_code)
        conn.commit()
    # FIX420.3.1.3 + FIX420.4.2.2.1: pass the original (unprepended)
    # message + the items list separately so the email builders can
    # render the IP / reply-to / items / subject / body sections
    # cleanly per spec.
    echo_message_id = _send_contact_email(
        subject=subject,
        message=message,
        sender_email=email,
        sender_ip=ip,
        sender_login=sender_login,
        items=items,
        project_name=project_name,
        lang_labels=lang_labels,
    )
    if echo_message_id:
        # Best-effort: link the echo's Resend id to the row so the
        # webhook can flip email_invalid later. Failure here is
        # non-fatal — worst case the bounce just isn't recorded.
        try:
            with pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "update contact_message set echo_message_id = %s "
                        "where id = %s",
                        (echo_message_id, row_id),
                    )
                conn.commit()
        except Exception:
            traceback.print_exc()
    return {"ok": True}


# ============================================================
# FIX420 (bounce detection): Resend webhook receiver. Configured
# once in Resend's dashboard with this URL + a signing secret in
# RESEND_WEBHOOK_SECRET. On a bounce or complaint we flip
# email_invalid on the matching contact_message row so the admin
# knows not to bother replying.
# ============================================================
RESEND_WEBHOOK_SECRET = os.environ.get("RESEND_WEBHOOK_SECRET")


def _verify_resend_signature(raw_body: bytes, headers) -> bool:
    """Svix-style verification: the signing input is
    '{svix-id}.{svix-timestamp}.{body}' and the signature header
    carries one or more 'v1,<base64>' entries. Any match wins.
    Returns False if the secret isn't set or any header is missing."""
    if not RESEND_WEBHOOK_SECRET:
        return False
    svix_id = headers.get("svix-id")
    svix_ts = headers.get("svix-timestamp")
    svix_sig = headers.get("svix-signature")
    if not (svix_id and svix_ts and svix_sig):
        return False
    secret = RESEND_WEBHOOK_SECRET
    # Strip the 'whsec_' prefix Resend hands out, then base64-decode.
    # Be liberal with the alphabet (URL-safe -/_ are allowed) and
    # missing '=' padding — both are common for whsec_ secrets.
    if secret.startswith("whsec_"):
        secret = secret[len("whsec_"):]
    padded = secret + "=" * (-len(secret) % 4)
    try:
        key = base64.urlsafe_b64decode(padded)
    except Exception:
        try:
            key = base64.b64decode(padded)
        except Exception as e:
            print(f"[webhook] secret base64 decode failed: {e!r}")
            return False
    signed_payload = f"{svix_id}.{svix_ts}.".encode() + raw_body
    expected = base64.b64encode(
        hmac.new(key, signed_payload, hashlib.sha256).digest()
    ).decode()
    # The header carries one or more space-separated 'v1,<sig>'
    # entries (key rotation can produce several). For each entry
    # the comma separates the version label from the signature
    # itself. Any match is enough.
    received: list = []
    for part in svix_sig.split():
        version, _, sig = part.partition(",")
        if version != "v1" or not sig:
            continue
        received.append(sig)
        if hmac.compare_digest(sig, expected):
            return True
    print(
        f"[webhook] signature mismatch — expected={expected!r} "
        f"received={received!r} key_len={len(key)}"
    )
    return False


@app.post("/api/webhooks/resend")
async def resend_webhook(request: Request):
    raw = await request.body()
    # Trace the bare delivery attempt so we know Resend reached us
    # at all, and what shape the payload has.
    snippet = raw[:500].decode("utf-8", errors="replace")
    svix_id = request.headers.get("svix-id")
    svix_ts = request.headers.get("svix-timestamp")
    svix_sig = request.headers.get("svix-signature")
    print(
        f"[webhook] received len={len(raw)} svix_id={svix_id!r} "
        f"svix_ts={svix_ts!r} svix_sig={svix_sig!r} body[:500]={snippet!r}"
    )
    if not _verify_resend_signature(raw, request.headers):
        print(
            "[webhook] signature rejected — "
            f"secret_set={bool(RESEND_WEBHOOK_SECRET)}"
        )
        raise HTTPException(status_code=401, detail="invalid signature")
    try:
        event = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")
    event_type = event.get("type") or ""
    data = event.get("data") or {}
    message_id = data.get("email_id") or data.get("id")
    print(
        f"[webhook] parsed event={event_type!r} message_id={message_id!r} "
        f"data_keys={list(data.keys())!r}"
    )
    # Resend's bounce events carry data.bounce.type ('Permanent' /
    # 'Transient'). We only flip the flag for permanent bounces and
    # spam complaints — soft bounces could be transient outages.
    if not message_id:
        return {"ok": True}
    invalid = False
    if event_type == "email.bounced":
        bounce = data.get("bounce") or {}
        if (bounce.get("type") or "").lower() == "permanent":
            invalid = True
    elif event_type == "email.complained":
        invalid = True
    elif event_type == "email.suppressed":
        # Resend put the address on its suppression list (typically
        # after a previous hard bounce or complaint). Same signal as
        # 'do not bother replying'.
        invalid = True
    if not invalid:
        return {"ok": True}
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "update contact_message set email_invalid = true "
                    "where echo_message_id = %s",
                    (message_id,),
                )
                rowcount = cur.rowcount
            conn.commit()
        print(f"[webhook] flagged {rowcount} row(s) for message_id={message_id!r}")
    except Exception:
        traceback.print_exc()
    return {"ok": True}


# ============================================================
# FIX421 <panel-message-list>: list of contact messages for the
# admin / project managers. Optional ?project_id=N filter restricts
# the list to one project (used when the panel is opened from a
# project's Admin menu — FIX421.1).
# ============================================================
@app.get("/api/admin/messages")
def list_contact_messages(
    project_id: Optional[int] = None,
    user=Depends(current_user_required),
):
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select is_admin from app_user where id = %s",
                (user["id"],),
            )
            pr = cur.fetchone()
            caller_is_admin = bool(pr and pr["is_admin"])
            # Non-admin callers see only messages tied to projects
            # they have any project_access row for.
            allowed_ids = None
            if not caller_is_admin:
                cur.execute(
                    "select project_id from project_access where user_id = %s",
                    (user["id"],),
                )
                allowed_ids = [r["project_id"] for r in cur.fetchall()]
                if not allowed_ids:
                    return []
            sql = (
                "select m.id, m.ts, m.ip, m.project_id, p.name as project_name, "
                "       m.sender_email, m.subject, m.body, m.email_invalid "
                "from contact_message m "
                "left join project p on p.id = m.project_id "
            )
            params: list = []
            where: list = []
            if project_id is not None:
                if not caller_is_admin and project_id not in allowed_ids:
                    raise HTTPException(status_code=403, detail="forbidden")
                where.append("m.project_id = %s")
                params.append(project_id)
            elif allowed_ids is not None:
                where.append("m.project_id = any(%s)")
                params.append(allowed_ids)
            if where:
                sql += "where " + " and ".join(where) + " "
            # FIX421.2.1.10: descending Date/time.
            sql += "order by m.ts desc limit 500"
            cur.execute(sql, tuple(params))
            rows = cur.fetchall()
    return [
        {
            "id": r["id"],
            "ts": r["ts"].isoformat(),
            # FIX421.2.1.8 + FIX421.4.1: surface the visitor's IP so the
            # admin panel can render either the IP or its friendly
            # name (when defined in <panel-ip-address-and-stats>).
            "ip": r["ip"],
            "project_id": r["project_id"],
            "project_name": r["project_name"],
            "sender_email": r["sender_email"],
            "subject": r["subject"],
            "body": r["body"],
            "email_invalid": bool(r["email_invalid"]),
        }
        for r in rows
    ]


# ============================================================
# FIX351 <panel-project-list>: admin-only project + managers
# management. 'Managers' = users with a project_access row for the
# project. FIX351 spec restricts managers to users that have a
# password set (FIX317 redeemed).
# ============================================================
def _check_managers_have_password(cur, manager_ids):
    if not manager_ids:
        return
    cur.execute(
        "select count(*) as c "
        "from app_user u "
        "left join auth.users au on au.id = u.id "
        "where u.id = any(%s::uuid[]) "
        "  and au.encrypted_password is null",
        (manager_ids,),
    )
    if cur.fetchone()["c"] > 0:
        raise HTTPException(
            status_code=400,
            detail="all managers must have a password set",
        )


@app.get("/api/admin/projects")
def list_admin_projects(user=Depends(current_user_required)):
    # FIX400.2.1.1: order matches the panel's stored sort order.
    # FIX351.2.1.2 / .1.5: a project_access row carries two roles
    # (is_data_manager, is_user_manager) — the response surfaces both
    # lists separately so the projects table can render them in their
    # own columns.
    # FIX351.2.1.6 <project-img-volume>: total image storage size per
    # project in bytes, surfaced as Volume (Mbytes) in the table.
    # FIX351.5.8: non-admin callers see only the projects where they
    # appear as data manager or user manager. Admins see every row.
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select is_admin from app_user where id = %s",
                (user["id"],),
            )
            pr = cur.fetchone()
            caller_is_admin = bool(pr and pr["is_admin"])
            if caller_is_admin:
                cur.execute(
                    "select id, name, is_public, sort_order, "
                    "       front_introduction, introduction, "
                    "       title_long_text, title_short_text, title_size, title_colour, title_is_bold "
                    "from project order by sort_order, id"
                )
            else:
                cur.execute(
                    "select p.id, p.name, p.is_public, p.sort_order, "
                    "       p.front_introduction, p.introduction, "
                    "       p.title_long_text, p.title_short_text, p.title_size, p.title_colour, p.title_is_bold "
                    "from project p "
                    "join project_access pa on pa.project_id = p.id "
                    "where pa.user_id = %s "
                    "  and (pa.is_data_manager or pa.is_user_manager "
                    "       or pa.is_layout_mngr or pa.is_setup_mngr) "
                    "group by p.id "
                    "order by p.sort_order, p.id",
                    (user["id"],),
                )
            projects = cur.fetchall()
            # FIX352.2.10 <project-slugs>: per-project slug list.
            cur.execute(
                "select project_id, label, is_official, is_active, sort_order "
                "from project_slug order by project_id, sort_order, id"
            )
            slug_rows = cur.fetchall()
            slugs_by_proj: dict[int, list] = {}
            for s in slug_rows:
                slugs_by_proj.setdefault(s["project_id"], []).append({
                    "label": s["label"],
                    "is_official": bool(s["is_official"]),
                    "is_active": bool(s["is_active"]),
                })
            cur.execute(
                "select pa.project_id, pa.user_id, u.login_name, "
                "       pa.is_viewer, pa.is_rater, pa.is_layout_mngr, "
                "       pa.is_data_manager, pa.is_user_manager, pa.is_setup_mngr "
                "from project_access pa "
                "join app_user u on u.id = pa.user_id "
                "order by u.login_name"
            )
            access_rows = cur.fetchall()
            # Aggregate image bytes per project. The inner CTE
            # de-duplicates (project_id, image_id) pairs so an image
            # linked to several folders of the same project counts
            # exactly once.
            cur.execute(
                """
                with proj_imgs as (
                    select distinct f.project_id, i.id as image_id, i.bytes
                      from image i
                      join folder_image fi on fi.image_id = i.id
                      join folder f       on f.id = fi.folder_id
                )
                select project_id,
                       coalesce(sum(bytes), 0) as bytes
                  from proj_imgs
                 group by project_id
                """,
            )
            bytes_rows = cur.fetchall()
    bytes_by_proj = {r["project_id"]: int(r["bytes"] or 0) for r in bytes_rows}
    # FIX300 / FIX351.2.1.{2,5,7,8,9,10}: one list per role, each keyed
    # off its own project_access boolean column.
    role_cols = {
        "viewers": "is_viewer",
        "raters": "is_rater",
        "layout_mngrs": "is_layout_mngr",
        "data_managers": "is_data_manager",
        "user_managers": "is_user_manager",
        "setup_mngrs": "is_setup_mngr",
    }
    by_role: dict[str, dict[int, list]] = {key: {} for key in role_cols}
    for r in access_rows:
        entry = {"id": str(r["user_id"]), "name": r["login_name"]}
        for key, col in role_cols.items():
            if r[col]:
                by_role[key].setdefault(r["project_id"], []).append(entry)
    return [
        {
            "id": p["id"],
            "name": p["name"],
            "is_public": bool(p["is_public"]),
            # `managers` kept for backward-compat callers — the union
            # of the data + user manager roles, deduped by user id.
            "managers": _dedup_by_id(
                by_role["data_managers"].get(p["id"], [])
                + by_role["user_managers"].get(p["id"], []),
            ),
            **{key: lists.get(p["id"], []) for key, lists in by_role.items()},
            "image_bytes": bytes_by_proj.get(p["id"], 0),
            # FIX352.2.5 / .2.6 / .2.10
            "front_introduction": p.get("front_introduction") or "",
            "introduction": p.get("introduction") or "",
            "slugs": slugs_by_proj.get(p["id"], []),
            # FIX352.2.7 <project-title>: optional decorative label
            # rendered in the project page header.
            "title_long_text": p.get("title_long_text") or "",
            "title_short_text": p.get("title_short_text") or "",
            "title_size": p.get("title_size"),
            "title_colour": p.get("title_colour"),
            "title_is_bold": bool(p.get("title_is_bold")),
        }
        for p in projects
    ]


def _dedup_by_id(items):
    seen = set()
    out = []
    for it in items:
        if it["id"] in seen:
            continue
        seen.add(it["id"])
        out.append(it)
    return out


@app.post("/api/admin/projects")
async def create_admin_project(request: Request, _admin=Depends(current_admin_required)):
    payload = await request.json() if await request.body() else {}
    name = (payload.get("name") or "").strip()
    # FIX351.2.1 (updated): create-time accepts multiple managers.
    # Accept the new manager_ids list; fall back to legacy singular
    # manager_id from older clients.
    manager_ids = payload.get("manager_ids")
    if not isinstance(manager_ids, list):
        legacy = (payload.get("manager_id") or "").strip()
        manager_ids = [legacy] if legacy else []
    manager_ids = [m for m in (manager_ids or []) if m]
    # FIX351.2.1.2 [ex-351.2.1.1]: non-blank, unique name.
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    # FIX351.2.1.2 (removed): managers can now be assigned later via
    # the user-projects editor (FIX311.3.3) — Add Project no longer
    # demands at least one manager.
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select 1 from project where name = %s", (name,))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="project name already in use")
            _check_managers_have_password(cur, manager_ids)
            # First manager (if any) becomes owner_id; the rest get
            # project_access rows. FIX351.2.1.3.1 + FIX400.2.1.{2,3}:
            # new projects are private by default — admin must flip
            # is_public on for them to appear to anyone.
            primary = manager_ids[0] if manager_ids else None
            # Append at the end of the order list (FIX351.2.7/.2.8).
            cur.execute(
                "select coalesce(max(sort_order), 0) + 10 as next "
                "from project"
            )
            next_order = cur.fetchone()["next"]
            cur.execute(
                "insert into project (name, owner_id, is_public, sort_order) "
                "values (%s, %s, false, %s) returning id, name",
                (name, primary, next_order),
            )
            row = cur.fetchone()
            # FIX350.2.3.1: every project must have a root folder that is
            # its Master Folder — properties hang off the folder, not the
            # project. Migration 005 backfilled this for legacy projects;
            # newly-created ones need it inserted here, otherwise the
            # property editor errors out on first save.
            cur.execute(
                "insert into folder (project_id, name, sort_order, is_master) "
                "values (%s, %s, 0, true)",
                (row["id"], name),
            )
            # New project's managers are full data + user managers.
            # The owner (first manager) is intentionally given both
            # roles so they can immediately assign access to others.
            for mid in manager_ids:
                cur.execute(
                    "insert into project_access "
                    "(user_id, project_id, is_data_manager, is_user_manager) "
                    "values (%s, %s, true, true)",
                    (mid, row["id"]),
                )
        conn.commit()
    return {"id": row["id"], "name": row["name"]}


@app.patch("/api/admin/projects/{project_id}")
async def update_admin_project(
    project_id: int,
    request: Request,
    user=Depends(current_user_required),
):
    """FIX352 <panel-project> persistence. Caller must be an admin OR a
    User Manager of the project (FIX351.5.7 + FIX352.3). Admins can
    also rewrite <project-user-managers> (FIX352.3.10.11); other
    callers are limited to name / data managers / is_public."""
    payload = await request.json() if await request.body() else {}
    new_name = payload.get("name")
    is_public = payload.get("is_public")  # bool or None to skip
    data_managers = payload.get("data_managers")
    user_managers = payload.get("user_managers")
    # FIX300: the other 4 roles, same "None = don't touch this role"
    # convention as data_managers / user_managers.
    viewers = payload.get("viewers")
    raters = payload.get("raters")
    layout_mngrs = payload.get("layout_mngrs")
    setup_mngrs = payload.get("setup_mngrs")
    # FIX352.2.5 / .2.6: free-form intros (None = skip; '' = clear).
    front_introduction = payload.get("front_introduction")
    introduction = payload.get("introduction")
    # FIX352.2.10 / FIX352.3.{2,3,4}: editable slug list.
    slugs = payload.get("slugs")  # list of {label, is_official, is_active} or None
    # FIX352.2.7 <project-title>: optional decorative label + style.
    # `null` clears the optional ones (size, colour); use empty
    # string to clear title_long_text / title_short_text. Each is
    # independently skip-able by omitting the key.
    has_title_long_text = "title_long_text" in payload
    has_title_short_text = "title_short_text" in payload
    has_title_size = "title_size" in payload
    has_title_colour = "title_colour" in payload
    has_title_is_bold = "title_is_bold" in payload
    # Backward compat: legacy clients send 'managers' meaning both
    # roles at once — treat the list as both data + user managers so
    # the row state matches the pre-split semantics.
    legacy_managers = (
        payload.get("managers")
        if data_managers is None and user_managers is None
        else None
    )
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select 1 from project where id = %s", (project_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="project not found")
            # FIX351.5.7: caller must be admin or User Manager of this
            # project. FIX352.3.10.11: only admins may touch
            # <project-user-managers>.
            cur.execute("select is_admin from app_user where id = %s", (user["id"],))
            pr = cur.fetchone()
            caller_is_admin = bool(pr and pr["is_admin"])
            if not caller_is_admin:
                cur.execute(
                    "select 1 from project_access "
                    "where user_id = %s and project_id = %s and is_user_manager",
                    (user["id"], project_id),
                )
                if not cur.fetchone():
                    raise HTTPException(
                        status_code=403,
                        detail="must be admin or User Manager of this project",
                    )
                if user_managers is not None or legacy_managers is not None:
                    raise HTTPException(
                        status_code=403,
                        detail="only admin can change user managers",
                    )
            # FIX351.2.1.3 / FIX400.2.1.{2,3}: <project-is-public> toggle.
            if is_public is not None:
                cur.execute(
                    "update project set is_public = %s where id = %s",
                    (bool(is_public), project_id),
                )
            # FIX352.3.10.1 [ex-351.2.3]: name must be non-blank and
            # unique across projects.
            if new_name is not None:
                new_name = new_name.strip()
                if not new_name:
                    raise HTTPException(status_code=400, detail="name cannot be empty")
                cur.execute(
                    "select 1 from project where name = %s and id != %s",
                    (new_name, project_id),
                )
                if cur.fetchone():
                    raise HTTPException(status_code=409, detail="project name already in use")
                cur.execute(
                    "update project set name = %s where id = %s",
                    (new_name, project_id),
                )
            # FIX300 / FIX352.3.10.10: each role is independently
            # settable — a role omitted from the payload (None) is left
            # exactly as it is in the DB; only roles the caller actually
            # sent get rewritten, so e.g. saving Data Managers never
            # wipes Viewers/Raters/User Managers/etc. A user newly
            # appearing in any sent role gets a project_access row
            # (is_viewer true by default per FIX300.3.10.1.1 — being
            # assigned to the project at all implies Viewer unless that
            # role is itself explicitly turned off in the same save).
            # Note: no `password set` precondition here — under the
            # new flow grant_user_project legitimately adds users that
            # haven't redeemed yet (FIX317). They appear as managers
            # but can't act as managers until they redeem.
            role_updates: dict[str, set] = {}
            if legacy_managers is not None:
                role_updates["is_data_manager"] = set(legacy_managers or [])
                role_updates["is_user_manager"] = set(legacy_managers or [])
            else:
                if viewers is not None:
                    role_updates["is_viewer"] = set(viewers or [])
                if raters is not None:
                    role_updates["is_rater"] = set(raters or [])
                if layout_mngrs is not None:
                    role_updates["is_layout_mngr"] = set(layout_mngrs or [])
                if data_managers is not None:
                    role_updates["is_data_manager"] = set(data_managers or [])
                if user_managers is not None:
                    role_updates["is_user_manager"] = set(user_managers or [])
                if setup_mngrs is not None:
                    role_updates["is_setup_mngr"] = set(setup_mngrs or [])
            if role_updates:
                all_uids: set = set()
                for uid_set in role_updates.values():
                    all_uids |= uid_set
                for uid in all_uids:
                    cur.execute(
                        "insert into project_access (user_id, project_id) "
                        "values (%s, %s) "
                        "on conflict (user_id, project_id) do nothing",
                        (uid, project_id),
                    )
                for col, uid_set in role_updates.items():
                    cur.execute(
                        f"update project_access set {col} = (user_id = any(%s::uuid[])) "
                        "where project_id = %s",
                        (list(uid_set), project_id),
                    )
                if "is_rater" in role_updates:
                    _sync_project_rater_for_project(cur, project_id)
            # FIX352.2.5 / .2.6: persist the introductions.
            if front_introduction is not None:
                cur.execute(
                    "update project set front_introduction = %s where id = %s",
                    (str(front_introduction), project_id),
                )
            if introduction is not None:
                cur.execute(
                    "update project set introduction = %s where id = %s",
                    (str(introduction), project_id),
                )
            # FIX352.2.7 <project-title>: persist the title fields. Each
            # is independently optional in the payload; only the keys
            # the client sent get written.
            if has_title_long_text:
                cur.execute(
                    "update project set title_long_text = %s where id = %s",
                    (str(payload.get("title_long_text") or ""), project_id),
                )
            if has_title_short_text:
                cur.execute(
                    "update project set title_short_text = %s where id = %s",
                    (str(payload.get("title_short_text") or ""), project_id),
                )
            if has_title_size:
                raw = payload.get("title_size")
                size_val: Optional[int]
                if raw in (None, ""):
                    size_val = None
                else:
                    try:
                        size_val = int(raw)
                        if size_val <= 0:
                            raise ValueError("title_size must be positive")
                    except (TypeError, ValueError):
                        raise HTTPException(
                            status_code=400, detail="title_size must be a positive integer",
                        )
                cur.execute(
                    "update project set title_size = %s where id = %s",
                    (size_val, project_id),
                )
            if has_title_colour:
                raw = payload.get("title_colour")
                colour = (raw or "").strip() or None
                # Accept #rgb / #rrggbb only; spec says 'Colour picker'
                # which typically yields hex.
                if colour is not None and not re.fullmatch(r"#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?", colour):
                    raise HTTPException(
                        status_code=400, detail="title_colour must be a hex colour like #rrggbb",
                    )
                cur.execute(
                    "update project set title_colour = %s where id = %s",
                    (colour, project_id),
                )
            if has_title_is_bold:
                cur.execute(
                    "update project set title_is_bold = %s where id = %s",
                    (bool(payload.get("title_is_bold")), project_id),
                )
            # FIX352.2.10 / FIX352.3.{2,3,4}: replace the slug list.
            # Validates non-empty labels and exactly one official entry.
            if slugs is not None:
                if not isinstance(slugs, list) or len(slugs) == 0:
                    raise HTTPException(
                        status_code=400, detail="slugs must be a non-empty list"
                    )
                cleaned = []
                official_count = 0
                seen_labels: set[str] = set()
                for s in slugs:
                    if not isinstance(s, dict):
                        raise HTTPException(status_code=400, detail="slug entry must be object")
                    label = (s.get("label") or "").strip()
                    if not label or not re.fullmatch(r"[a-z0-9]+", label):
                        raise HTTPException(
                            status_code=400,
                            detail=f"invalid slug label: {label!r}",
                        )
                    if label in seen_labels:
                        raise HTTPException(
                            status_code=400, detail=f"duplicate slug label: {label}",
                        )
                    seen_labels.add(label)
                    is_official = bool(s.get("is_official"))
                    is_active = bool(s.get("is_active"))
                    if is_official:
                        official_count += 1
                        # FIX352.3.4.2: official is always active.
                        is_active = True
                    cleaned.append((label, is_official, is_active))
                if official_count != 1:
                    raise HTTPException(
                        status_code=400,
                        detail="exactly one slug must be official",
                    )
                # FIX352.3.4.2 cross-project rule: an active label must
                # be globally unique. Reject up-front rather than rely
                # on the DB constraint so the error stays user-readable.
                cur.execute(
                    "select label from project_slug "
                    "where project_id != %s and is_active "
                    "  and label = any(%s)",
                    (project_id, [c[0] for c in cleaned if c[2]]),
                )
                clash = cur.fetchone()
                if clash:
                    raise HTTPException(
                        status_code=409,
                        detail=f"slug already used by another project: {clash['label']}",
                    )
                cur.execute(
                    "delete from project_slug where project_id = %s",
                    (project_id,),
                )
                for i, (label, is_official, is_active) in enumerate(cleaned):
                    cur.execute(
                        "insert into project_slug "
                        "(project_id, label, is_official, is_active, sort_order) "
                        "values (%s, %s, %s, %s, %s)",
                        (project_id, label, is_official, is_active, i),
                    )
        conn.commit()
    return {"ok": True}


# FIX414 <panel-app-versions>: combined deploy history for the
# Render backend and the Vercel frontend. Admin-only. Each platform
# response is normalized to a common shape so the UI can render the
# two lists side-by-side without dealing with provider quirks.
#
# Required env vars (set on Render):
#   RENDER_API_KEY     — generate at https://dashboard.render.com/u/settings/api-keys
#   RENDER_SERVICE_ID  — e.g. srv-XXXX, from the service URL
#   VERCEL_TOKEN       — generate at https://vercel.com/account/tokens
#   VERCEL_PROJECT_ID  — prj_XXXX, from the project's settings page
# When a token is missing, that platform's section returns an empty
# list with a `note` field — the panel still renders the other side.
def _http_get_json(url: str, headers: dict, timeout: int = 10):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _short_sha(sha: Optional[str]) -> Optional[str]:
    return sha[:7] if isinstance(sha, str) and sha else None


def _normalize_render_status(s: str) -> str:
    s = (s or "").lower()
    if s == "live":
        return "live"
    # 'deactivated' = was live, then superseded by a newer deploy.
    # Treat as a successful past deploy, NOT a failure.
    if s in ("deactivated", "succeeded"):
        return "succeeded"
    if "in_progress" in s or s in ("created", "queued"):
        return "building"
    if "failed" in s or s == "canceled":
        return "failed"
    return s or "unknown"


def _normalize_vercel_status(s: str) -> str:
    # Vercel's `state` doesn't say "this one is currently serving" — every
    # historical successful prod deploy stays READY forever. The caller
    # marks only the most recent READY as 'live' and downgrades the rest
    # to 'succeeded'; this function only resolves the raw state string.
    s = (s or "").upper()
    if s == "READY":
        return "succeeded"
    if s in ("BUILDING", "QUEUED", "INITIALIZING"):
        return "building"
    if s in ("ERROR", "CANCELED"):
        return "failed"
    return s.lower() or "unknown"


def _ms_to_iso(ms: Optional[int]) -> Optional[str]:
    if not ms:
        return None
    try:
        return datetime.utcfromtimestamp(int(ms) / 1000).isoformat() + "Z"
    except Exception:
        return None


def _fetch_render_deploys() -> dict:
    api_key = os.getenv("RENDER_API_KEY")
    service_id = os.getenv("RENDER_SERVICE_ID")
    if not api_key or not service_id:
        return {"deploys": [], "note": "RENDER_API_KEY / RENDER_SERVICE_ID not set"}
    try:
        data = _http_get_json(
            f"https://api.render.com/v1/services/{service_id}/deploys?limit=20",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            },
        )
    except Exception as e:
        return {"deploys": [], "note": f"Render API error: {e}"}
    out = []
    for entry in data or []:
        d = entry.get("deploy") if isinstance(entry, dict) else None
        if not d:
            continue
        commit = (d.get("commit") or {})
        out.append({
            "sha": _short_sha(commit.get("id")),
            "sha_full": commit.get("id"),
            "message": (commit.get("message") or "").splitlines()[0] if commit.get("message") else None,
            "status": _normalize_render_status(d.get("status")),
            "raw_status": d.get("status"),
            "created_at": d.get("createdAt"),
            "effective_at": d.get("finishedAt") or d.get("updatedAt"),
            "url": None,  # Render dashboard URL would need the team slug
        })
    return {"deploys": out, "note": None}


def _fetch_vercel_deploys() -> dict:
    token = os.getenv("VERCEL_TOKEN")
    project_id = os.getenv("VERCEL_PROJECT_ID")
    if not token or not project_id:
        return {"deploys": [], "note": "VERCEL_TOKEN / VERCEL_PROJECT_ID not set"}
    try:
        # target=production filters out preview branch deploys so the
        # panel only shows what was meant for the live site.
        data = _http_get_json(
            f"https://api.vercel.com/v6/deployments"
            f"?projectId={project_id}&target=production&limit=20",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )
    except Exception as e:
        return {"deploys": [], "note": f"Vercel API error: {e}"}
    out = []
    promoted_live = False  # only the first READY deploy becomes 'live'.
    for d in (data or {}).get("deployments", []) or []:
        meta = d.get("meta") or {}
        sha_full = (
            meta.get("githubCommitSha")
            or meta.get("gitlabCommitSha")
            or meta.get("bitbucketCommitSha")
        )
        message = meta.get("githubCommitMessage") or meta.get("gitlabCommitMessage")
        status = _normalize_vercel_status(d.get("state") or d.get("readyState"))
        if status == "succeeded" and not promoted_live:
            status = "live"
            promoted_live = True
        out.append({
            "sha": _short_sha(sha_full),
            "sha_full": sha_full,
            "message": (message or "").splitlines()[0] if message else None,
            "status": status,
            "raw_status": d.get("state") or d.get("readyState"),
            "created_at": _ms_to_iso(d.get("created")),
            "effective_at": _ms_to_iso(d.get("ready") or d.get("created")),
            "url": ("https://" + d["url"]) if d.get("url") else None,
        })
    return {"deploys": out, "note": None}


@app.get("/api/admin/versions")
def list_versions(_admin=Depends(current_admin_required)):
    """FIX414 <panel-app-versions>: deploy history for both halves
    of the stack. Returns the 20 most recent deploys per platform
    with a normalized status (live / building / failed)."""
    return {
        "backend": _fetch_render_deploys(),
        "frontend": _fetch_vercel_deploys(),
    }


# ============================================================
# FIX509 <panel-language-setup>: i18n storage. The full list of
# languages + their per-key label maps. Public GET /api/languages
# (anyone can resolve labels), admin-only writes.
# ============================================================
def _clean_labels_payload(obj, depth: int = 0):
    """Recursively coerce a labels payload into a clean JSON-friendly
    shape. Top level: { 'NNN. section': { 'key': 'value' } }.
    Strings stay strings, dicts recurse one level, anything else is
    dropped. Cap depth at 2 so a malformed deep payload can't blow
    up the JSONB column."""
    if depth > 2 or not isinstance(obj, dict):
        return {} if isinstance(obj, dict) else None
    out: dict = {}
    for k, v in obj.items():
        if v is None:
            continue
        if isinstance(v, dict):
            sub = _clean_labels_payload(v, depth + 1)
            if sub:
                out[str(k)] = sub
        elif isinstance(v, (str, int, float, bool)):
            out[str(k)] = str(v)
    return out


def _row_to_language(r: dict) -> dict:
    return {
        "code": r["code"],
        "name": r["name"],
        "is_default": bool(r["is_default"]),
        "labels": r["labels"] or {},
        "sort_order": r["sort_order"],
    }


@app.get("/api/languages")
def list_languages():
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select code, name, is_default, labels, sort_order "
                "from language order by sort_order, code"
            )
            rows = cur.fetchall()
    return [_row_to_language(r) for r in rows]


_LANG_CODE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,15}$")


def _validate_language_code(code: str) -> str:
    code = (code or "").strip()
    if not _LANG_CODE_RE.match(code):
        raise HTTPException(
            status_code=400,
            detail="code must be 1–16 chars, [A-Za-z0-9_-], starting with a letter",
        )
    return code


@app.post("/api/admin/languages")
async def create_language(request: Request, _admin=Depends(current_admin_required)):
    payload = await request.json() if await request.body() else {}
    code = _validate_language_code(payload.get("code") or "")
    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name required")
    is_default = bool(payload.get("is_default"))
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select 1 from language where code = %s", (code,))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="language already exists")
            # Append to the end of the order list.
            cur.execute(
                "select coalesce(max(sort_order), -1) + 1 as next from language"
            )
            next_order = cur.fetchone()["next"]
            if is_default:
                # Only one default at a time — clear the existing one first.
                cur.execute("update language set is_default = false where is_default")
            cur.execute(
                "insert into language (code, name, is_default, sort_order) "
                "values (%s, %s, %s, %s) "
                "returning code, name, is_default, labels, sort_order",
                (code, name, is_default, next_order),
            )
            row = cur.fetchone()
        conn.commit()
    return _row_to_language(row)


@app.patch("/api/admin/languages/{code}")
async def update_language(
    code: str,
    request: Request,
    _admin=Depends(current_admin_required),
):
    payload = await request.json() if await request.body() else {}
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select 1 from language where code = %s", (code,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="language not found")
            if "name" in payload:
                name = (payload.get("name") or "").strip()
                if not name:
                    raise HTTPException(status_code=400, detail="name cannot be empty")
                cur.execute(
                    "update language set name = %s where code = %s",
                    (name, code),
                )
            if "is_default" in payload:
                if payload.get("is_default"):
                    cur.execute(
                        "update language set is_default = false "
                        "where is_default and code != %s",
                        (code,),
                    )
                    cur.execute(
                        "update language set is_default = true where code = %s",
                        (code,),
                    )
                else:
                    cur.execute(
                        "update language set is_default = false where code = %s",
                        (code,),
                    )
            if "labels" in payload:
                labels = payload.get("labels")
                if not isinstance(labels, dict):
                    raise HTTPException(status_code=400, detail="labels must be an object")
                # FIX509 v2: labels are nested by section, e.g.
                #   { '420. Contact panel': { 'Cancel': 'Annuler' } }
                # Recursively keep the dict shape intact — the previous
                # implementation stringified top-level values, which
                # destroyed the nested sections (str({'Cancel':'X'})
                # produces a Python repr, not JSON).
                cleaned = _clean_labels_payload(labels)
                cur.execute(
                    "update language set labels = %s::jsonb where code = %s",
                    (json.dumps(cleaned), code),
                )
            cur.execute(
                "select code, name, is_default, labels, sort_order "
                "from language where code = %s",
                (code,),
            )
            row = cur.fetchone()
        conn.commit()
    return _row_to_language(row)


@app.delete("/api/admin/languages/{code}")
def delete_language(code: str, _admin=Depends(current_admin_required)):
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select is_default from language where code = %s", (code,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="language not found")
            if row["is_default"]:
                raise HTTPException(
                    status_code=400,
                    detail="cannot delete the default language",
                )
            cur.execute("delete from language where code = %s", (code,))
        conn.commit()
    return {"ok": True}


@app.post("/api/admin/projects/{project_id}/move")
async def move_admin_project(
    project_id: int,
    request: Request,
    _admin=Depends(current_admin_required),
):
    """FIX351.2.7 / FIX351.2.8: swap sort_order with the previous
    (direction='up') or next (direction='down') project in the panel
    order. No-ops at the bounds — the buttons should already be
    disabled there."""
    payload = await request.json() if await request.body() else {}
    direction = (payload.get("direction") or "").strip()
    if direction not in ("up", "down"):
        raise HTTPException(status_code=400, detail="direction must be 'up' or 'down'")
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select id, sort_order from project where id = %s",
                (project_id,),
            )
            me = cur.fetchone()
            if not me:
                raise HTTPException(status_code=404, detail="project not found")
            if direction == "up":
                cur.execute(
                    "select id, sort_order from project "
                    "where (sort_order, id) < (%s, %s) "
                    "order by sort_order desc, id desc limit 1",
                    (me["sort_order"], me["id"]),
                )
            else:
                cur.execute(
                    "select id, sort_order from project "
                    "where (sort_order, id) > (%s, %s) "
                    "order by sort_order asc, id asc limit 1",
                    (me["sort_order"], me["id"]),
                )
            neighbour = cur.fetchone()
            if not neighbour:
                # Already at the requested edge — silently no-op.
                return {"ok": True}
            # If the neighbour shares the same sort_order, just decrement
            # / increment ours; otherwise swap the two values.
            if neighbour["sort_order"] == me["sort_order"]:
                delta = -1 if direction == "up" else 1
                cur.execute(
                    "update project set sort_order = sort_order + %s where id = %s",
                    (delta, me["id"]),
                )
            else:
                cur.execute(
                    "update project set sort_order = %s where id = %s",
                    (neighbour["sort_order"], me["id"]),
                )
                cur.execute(
                    "update project set sort_order = %s where id = %s",
                    (me["sort_order"], neighbour["id"]),
                )
        conn.commit()
    return {"ok": True}


@app.post("/api/admin/projects/{project_id}/clear-managers")
def clear_project_managers(project_id: int, _admin=Depends(current_admin_required)):
    # FIX351.2.2: Remove button clears managers — does NOT delete the
    # project itself (per spec, an "abandoned" project is allowed).
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "delete from project_access where project_id = %s",
                (project_id,),
            )
            cur.execute(
                "delete from project_rater where project_id = %s",
                (project_id,),
            )
        conn.commit()
    return {"ok": True}


@app.patch("/api/admin/users/{user_id}")
async def update_user(
    user_id: str,
    request: Request,
    _admin=Depends(current_admin_required),
):
    """FIX311.5.4 / FIX311.5.5: rename or change the email of an
    existing user. Both fields stay unique across app_user."""
    payload = await request.json() if await request.body() else {}
    name = payload.get("name")
    email = payload.get("email")
    if name is None and email is None:
        return {"ok": True}
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select 1 from app_user where id = %s", (user_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="user not found")
            if name is not None:
                name = name.strip()
                if not name:
                    raise HTTPException(status_code=400, detail="name cannot be empty")
                cur.execute(
                    "select 1 from app_user "
                    "where lower(login_name) = lower(%s) and id != %s",
                    (name, user_id),
                )
                if cur.fetchone():
                    raise HTTPException(status_code=409, detail="name already in use")
                cur.execute(
                    "update app_user set login_name = %s where id = %s",
                    (name, user_id),
                )
            if email is not None:
                email = email.strip()
                if not email:
                    raise HTTPException(status_code=400, detail="email cannot be empty")
                cur.execute(
                    "select 1 from app_user where email = %s and id != %s",
                    (email, user_id),
                )
                if cur.fetchone():
                    raise HTTPException(status_code=409, detail="email already in use")
                cur.execute(
                    "update app_user set email = %s where id = %s",
                    (email, user_id),
                )
        conn.commit()
    return {"ok": True}


@app.delete("/api/admin/users/{user_id}")
def delete_user(user_id: str, admin=Depends(current_admin_required)):
    # FIX311.5.8: project_access has on-delete-cascade on user_id, so
    # removing the app_user row also clears every manager assignment.
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="cannot remove yourself")
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("delete from app_user where id = %s", (user_id,))
            removed = cur.rowcount
        conn.commit()
    if removed == 0:
        raise HTTPException(status_code=404, detail="user not found")
    return {"ok": True}


@app.post("/api/admin/users/{user_id}/reset-password")
def reset_user_password(user_id: str, _admin=Depends(current_admin_required)):
    """FIX318 <process-reset-pswd>: triggered by <btn-reset-pswd>
    (FIX312.3.1). Same principle as user creation (FIX318.1 /
    FIX311.3.1.1.3): issue a fresh access code and clear the existing
    password so the user redeems again via <panel-sign-in-with
    access-code> (FIX406) at next login. FIX405.4.1.2 points a
    locked-out user at exactly this action, so it's also the one place
    <user-is-locked-out> gets cleared (nothing else does)."""
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select 1 from app_user where id = %s", (user_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="user not found")
            # FIX318.2.1: fresh 6-digit code, same generation as FIX311.3.1.1.3.
            access_code = f"{secrets.randbelow(1000000):06d}"
            cur.execute(
                "update app_user set access_code = %s, "
                "       failed_signin_attempts = 0, is_locked_out = false "
                "where id = %s",
                (access_code, user_id),
            )
        conn.commit()
    # FIX318.2.2: clear the existing password / unset <user-has-password>.
    _supabase_admin_delete_user(user_id)
    return {"ok": True}


def _require_admin_or_user_manager_of(cur, caller_id: str, project_id: int) -> None:
    """FIX311.5.6 / FIX312.4.2: editing a user's <user-projects> entry
    for project P is allowed only when the caller is a global admin
    OR a User Manager of P (project_access row with is_user_manager
    true). Plain Data Managers cannot grant access to others."""
    cur.execute("select is_admin from app_user where id = %s", (caller_id,))
    pr = cur.fetchone()
    if pr and pr["is_admin"]:
        return
    cur.execute(
        "select 1 from project_access "
        "where user_id = %s and project_id = %s and is_user_manager",
        (caller_id, project_id),
    )
    if not cur.fetchone():
        raise HTTPException(
            status_code=403,
            detail="must be admin or a User Manager of this project",
        )


def _sync_project_rater_for_project(cur, project_id):
    """FIX507.2.3(removed) / FIX300 <role-rater>: project_rater is a
    plain (project_id, user_id) mirror of project_access.is_rater --
    kept only so existing view_setup grouping columns
    ({"type": "user_rating", "rater_id": N}) keep resolving to a
    stable id (see migration 043). Call after any change to is_rater
    for this project."""
    cur.execute(
        "insert into project_rater (project_id, user_id) "
        "select project_id, user_id from project_access "
        "where project_id = %s and is_rater "
        "on conflict (project_id, user_id) do nothing",
        (project_id,),
    )
    cur.execute(
        "delete from project_rater where project_id = %s and user_id != all("
        "  select user_id from project_access "
        "  where project_id = %s and is_rater"
        ")",
        (project_id, project_id),
    )


def _compute_conflict_folder_ids(ratings_by_folder, rank_by_value_id, threshold, comparator):
    """FIX520.4.7 <rating-conflict-detection>: flags an item where two or
    more raters (any two) each have a <rating-rank> (1-based --
    rating_value.sort_order + 1, FIX507.2.2.1.3) that satisfies
    <rating-rank> {comparator} {threshold} (FIX507.2.6 / FIX507.2.5).
    Pure function over already-fetched data so both get_showcase (per
    request) and _save_setup_impl's FIX507.4.6 reassessment (on every
    Rating-tab save) share the exact same counting logic."""
    def _is_high(rv_id):
        rank = rank_by_value_id.get(rv_id)
        if rank is None:
            return False
        return rank < threshold if comparator == '<' else rank > threshold

    conflict_folder_ids = set()
    for folder_id, by_user in ratings_by_folder.items():
        high_count = sum(1 for rv_id in by_user.values() if _is_high(rv_id))
        if high_count >= 2:
            conflict_folder_ids.add(folder_id)
    return conflict_folder_ids


@app.post("/api/admin/users/{user_id}/projects/{project_id}")
def grant_user_project(
    user_id: str,
    project_id: int,
    caller=Depends(current_user_required),
):
    """FIX311.3.3 + FIX311.5.6: link `user_id` to `project_id` by
    inserting a project_access row (= adds the project to the user's
    <user-projects>). Idempotent: re-granting an existing row is a
    no-op."""
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            _require_admin_or_user_manager_of(cur, caller["id"], project_id)
            cur.execute("select 1 from app_user where id = %s", (user_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="user not found")
            cur.execute("select 1 from project where id = %s", (project_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="project not found")
            # FIX300.3.10.1.1: new row defaults to Viewer only (the
            # is_viewer column default) -- every other role, including
            # Data/User Manager, is granted separately via
            # <panel-project> (FIX352.3.10.10).
            cur.execute(
                "insert into project_access (user_id, project_id) "
                "values (%s, %s) "
                "on conflict (user_id, project_id) do nothing",
                (user_id, project_id),
            )
        conn.commit()
    return {"ok": True}


@app.delete("/api/admin/users/{user_id}/projects/{project_id}")
def revoke_user_project(
    user_id: str,
    project_id: int,
    caller=Depends(current_user_required),
):
    """FIX311.3.3 + FIX311.5.6 + FIX311.5.7: unlink `user_id` from
    `project_id`. Removes the project_access row, which is the same
    storage behind <user-projects> and <project-managers>, so the
    user is implicitly removed from the project's managers too."""
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            _require_admin_or_user_manager_of(cur, caller["id"], project_id)
            cur.execute(
                "delete from project_access "
                "where user_id = %s and project_id = %s",
                (user_id, project_id),
            )
            # Losing project access entirely also drops <role-rater>.
            cur.execute(
                "delete from project_rater where user_id = %s and project_id = %s",
                (user_id, project_id),
            )
        conn.commit()
    return {"ok": True}


@app.post("/api/admin/ip-name")
async def set_ip_name(request: Request, _user=Depends(current_user_required)):
    payload = await request.json() if await request.body() else {}
    ip = (payload.get("ip") or "").strip()
    name = (payload.get("name") or "").strip()
    if not ip:
        raise HTTPException(status_code=400, detail="ip required")
    with pool.connection() as conn:
        with conn.cursor() as cur:
            if name == "":
                cur.execute("delete from ip_name where ip = %s", (ip,))
            else:
                cur.execute(
                    "insert into ip_name (ip, name) values (%s, %s) "
                    "on conflict (ip) do update set name = excluded.name",
                    (ip, name),
                )
        conn.commit()
    return {"ok": True}


# ============================================================
# FIX400: list projects visible to caller
# ============================================================
@app.get("/api/projects")
def list_projects(user=Depends(current_user_optional)):
    """
    FIX400.2.1.1: ordered by sort_order (then id), matching the admin
    panel's order (FIX351.2.7 / FIX351.2.8).
    FIX400.2.1.2: is_public projects are visible to anyone.
    FIX400.2.1.3: private projects are visible only to the admin user
    and to the project's managers (project_access rows). The owner
    inherits visibility too — first successful edit claims ownership
    via PATCH /api/projects/:id below, so unowned-OR-owner is the
    historical proxy for the same intent.
    """
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            if user is None:
                cur.execute(
                    "select id, name, cover_image_key, is_public, "
                    "       front_introduction, "
                    "       false as can_edit "
                    "from project where is_public "
                    "order by sort_order, id"
                )
            else:
                # Admins see every project regardless of visibility flags.
                cur.execute(
                    "select is_admin from app_user where id = %s",
                    (user["id"],),
                )
                pr = cur.fetchone()
                is_caller_admin = bool(pr and pr["is_admin"])
                if is_caller_admin:
                    cur.execute(
                        "select p.id, p.name, p.cover_image_key, p.is_public, "
                        "       p.front_introduction, "
                        "       true as can_edit "
                        "from project p "
                        "order by p.sort_order, p.id"
                    )
                else:
                    # Use EXISTS instead of LEFT JOIN + DISTINCT — the
                    # join would otherwise produce one row per project
                    # access entry, and Postgres rejects ORDER BY on
                    # a column that isn't in a SELECT DISTINCT list.
                    cur.execute(
                        "select p.id, p.name, p.cover_image_key, p.is_public, "
                        "       p.front_introduction, "
                        "       (p.owner_id = %s or p.owner_id is null) as can_edit "
                        "from project p "
                        "where p.is_public "
                        "   or p.owner_id = %s "
                        "   or exists ("
                        "     select 1 from project_access pa "
                        "     where pa.project_id = p.id and pa.user_id = %s"
                        "   ) "
                        "order by p.sort_order, p.id",
                        (user["id"], user["id"], user["id"]),
                    )
            rows = cur.fetchall()
            # Map each project id → its current official slug so the
            # frontend can link to a stable URL even after a rename
            # (FIX352.3.4.1). Missing (legacy) projects fall back to a
            # JS-equivalent slugify of the name in the response.
            cur.execute(
                "select project_id, label "
                "from project_slug where is_official"
            )
            official_by_proj = {r["project_id"]: r["label"] for r in cur.fetchall()}
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "is_public": r["is_public"],
            "can_edit": bool(r["can_edit"]),
            "cover_image_url": (
                public_image_url(r["cover_image_key"]) if r["cover_image_key"] else None
            ),
            "front_introduction": r.get("front_introduction") or "",
            "official_slug": (
                official_by_proj.get(r["id"]) or _slugify_name(r["name"])
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
            # Allow: a global admin (regardless of owner_id — an orphaned or
            # mismatched owner_id must never lock an admin out; "who's logged
            # into the app" is what matters, not which identity happens to
            # be recorded as owner), the owner, or anyone if the project is
            # still unowned — in which case we auto-claim ownership below so
            # subsequent edits stick to this user.
            cur.execute("select is_admin from app_user where id = %s", (user["id"],))
            pr = cur.fetchone()
            is_admin = bool(pr and pr["is_admin"])
            if not is_admin and row["owner_id"] is not None and row["owner_id"] != user["id"]:
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
            # edited by any signed-in user (the PATCH that follows will
            # auto-claim ownership on save), and a global admin always
            # passes regardless of owner_id (see PATCH /api/projects/:id
            # for why: an orphaned/mismatched owner_id must never lock an
            # admin out).
            cur.execute("select is_admin from app_user where id = %s", (user["id"],))
            pr = cur.fetchone()
            is_admin = bool(pr and pr["is_admin"])
            if not is_admin and row["owner_id"] is not None and row["owner_id"] != user["id"]:
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
    try:
        signed_url = s3().generate_presigned_url(
            "put_object",
            Params={"Bucket": R2_BUCKET, "Key": storage_key},
            ExpiresIn=600,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Sign upload failed: {e}")
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


# FIX401.2: same slug recipe as the SPA router. Match project names
# in Python so the URL and the DB row map to the same project even
# when the name has accents / spaces / case differences.
def _slugify_name(name: str) -> str:
    nfd = unicodedata.normalize("NFD", name or "")
    plain = "".join(c for c in nfd if unicodedata.category(c) != "Mn")
    return re.sub(r"[^a-z0-9]+", "", plain.lower())


@app.get("/api/showcase")
def showcase(slug: Optional[str] = None, user=Depends(current_user_optional)):
    """FIX401.2: scoped to one project. With ?slug= the route resolves
    that specific project; without it (legacy callers) we still pick
    the first project in panel order so old single-project clients
    keep working.
    FIX503.5.1: also surfaces an `is_admin_or_manager` flag so the
    Showcase header can hide admin-only affordances (Import menu,
    Grouping, Setup, Admin menu) from anonymous and non-manager users."""
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            if slug:
                # FIX352.2.10 + FIX352.3.4: resolve the URL slug against
                # the project_slug table — any *active* slug for the
                # project resolves it, so URLs from before a rename
                # keep working as long as their slug stays active.
                cur.execute(
                    "select p.id, p.name, p.is_public, p.view_setup, p.enable_rating, "
                    "       p.show_rating_conflict, p.rating_conflict_threshold, "
                    "       p.rating_conflict_comparator, "
                    "       p.front_introduction, p.introduction, "
                    "       p.title_long_text, p.title_short_text, p.title_size, p.title_colour, p.title_is_bold "
                    "from project p "
                    "join project_slug s on s.project_id = p.id "
                    "where s.label = %s and s.is_active "
                    "limit 1",
                    (slug,),
                )
                project = cur.fetchone()
                if not project:
                    # Legacy fallback: pre-migration projects whose
                    # slug rows haven't been backfilled yet still
                    # resolve via the JS-equivalent slugify of the
                    # project name. Drop this once the migration has
                    # run on every environment.
                    cur.execute(
                        "select id, name, view_setup, enable_rating, "
                        "       show_rating_conflict, rating_conflict_threshold, "
                        "       rating_conflict_comparator, "
                        "       front_introduction, introduction, "
                        "       title_long_text, title_short_text, title_size, title_colour, title_is_bold "
                        "from project order by sort_order, id"
                    )
                    rows = cur.fetchall()
                    project = next(
                        (r for r in rows if _slugify_name(r["name"]) == slug),
                        None,
                    )
                if not project:
                    raise HTTPException(status_code=404, detail="project not found")
            else:
                cur.execute(
                    "select id, name, is_public, view_setup, enable_rating, "
                    "       show_rating_conflict, rating_conflict_threshold, "
                    "       rating_conflict_comparator, "
                    "       front_introduction, introduction, "
                    "       title_long_text, title_short_text, title_size, title_colour, title_is_bold "
                    "from project "
                    "order by sort_order, id limit 1"
                )
                project = cur.fetchone()
            if not project:
                # FIX401.2.1: a brand-new (and only) project may have no
                # data yet. Return empty arrays — the frontend renders
                # the empty showcase gracefully.
                return {
                    "project": None,
                    "properties": [],
                    "view_setup": {},
                    "folders": [],
                    "rating_setup": {
                        "enabled": False, "values": [], "raters": [],
                        "show_conflict": False, "conflict_threshold": 2,
                    },
                }
            # FIX503.4.1: caller is admin (global role) or Manager of the
            # project (Users listed in <project-managers>, i.e. the Data
            # Managers column / is_data_manager -- FIX351.2.1.2). Bug fix:
            # this used to accept *any* project_access row, which also
            # matched a User-Manager-only row (is_user_manager, a
            # narrower role -- FIX312.4.2 -- that only grants/revokes
            # other users' project access, not the admin-gated UI here),
            # incorrectly showing <menu-admin> and the other FIX503.4.1
            # affordances to callers who aren't actually Data Managers.
            is_admin_or_manager = False
            caller_is_admin = False
            # FIX300.3.10.3.2 / FIX300.3.10.6.2: <button-item-grouping> /
            # <button-columns> gate on Layout Manager, <button-setup>
            # gates on Setup Manager -- both admin-exempt like every
            # other role check here.
            is_layout_mngr = False
            is_setup_mngr = False
            if user is not None:
                cur.execute(
                    "select is_admin from app_user where id = %s",
                    (user["id"],),
                )
                pr = cur.fetchone()
                caller_is_admin = bool(pr and pr["is_admin"])
                if caller_is_admin:
                    is_admin_or_manager = True
                    is_layout_mngr = True
                    is_setup_mngr = True
                else:
                    cur.execute(
                        "select is_data_manager, is_layout_mngr, is_setup_mngr "
                        "from project_access "
                        "where project_id = %s and user_id = %s",
                        (project["id"], user["id"]),
                    )
                    pa = cur.fetchone()
                    is_admin_or_manager = bool(pa and pa["is_data_manager"])
                    is_layout_mngr = bool(pa and pa["is_layout_mngr"])
                    is_setup_mngr = bool(pa and pa["is_setup_mngr"])
            # FIX410.1.1.6.2: "no one can open any project ... admin
            # excepted". Frontend already redirects away from the project
            # route in this state; this is the API-level backstop for a
            # direct call.
            if not caller_is_admin and _maintenance_enabled():
                raise HTTPException(status_code=503, detail="site is in maintenance")
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
                  f.zoom_factor,
                  f.is_flagged,
                  img.storage_key as main_storage_key,
                  img.rotation    as main_rotation,
                  img.thumb_created_at as main_thumb_created_at,
                  img.created_at as main_created_at,
                  exists (select 1 from folder_image where folder_id = f.id) as has_image,
                  -- FIX504.2.1.2.2.4 <Image size>: total bytes of this item's
                  -- images, summed from the image table's stored byte size.
                  coalesce((
                    select sum(i2.bytes)
                      from folder_image fi2
                      join image i2 on i2.id = fi2.image_id
                     where fi2.folder_id = f.id
                  ), 0) as image_bytes
                from folder f
                -- Bug fix: this used to inner-require fi.is_main, so an item
                -- with images but none explicitly flagged main (nobody ever
                -- picked one) got a null main_image_url even though
                -- has_image was true -- e.g. FIX702's rated-images grid
                -- silently dropped such items despite them counting toward
                -- the rating's total. Falls back to the lowest-sort_order
                -- image when no image is flagged is_main.
                left join lateral (
                  select mfi.image_id
                  from folder_image mfi
                  where mfi.folder_id = f.id
                  order by mfi.is_main desc, mfi.sort_order, mfi.id
                  limit 1
                ) main_fi on true
                left join image img on img.id = main_fi.image_id
                where f.project_id = %s and not f.is_master
                order by f.sort_order, f.id
                """,
                (project["id"],),
            )
            rows = cur.fetchall()
            # FIX507.2.2.1 <table-rating-values>: text + icon rows.
            # Bug fix: sort_order was never actually sent to the client
            # (only used server-side for the ORDER BY) -- every client-side
            # use of rv.sort_order (rating-conflict-detection's rank math,
            # FIX511.4.3's gallery-strip-by-rank sort, the my_rating
            # column's sort value) silently computed NaN/undefined forever.
            cur.execute(
                "select id, text, icon, sort_order from rating_value "
                "where project_id = %s order by sort_order, id",
                (project["id"],),
            )
            rating_values = cur.fetchall()
            # FIX300 <role-rater> / FIX507.2.3(removed): project_rater is
            # kept in sync with project_access.is_rater (see
            # _sync_project_rater_for_project) purely so its id stays a
            # stable rater_id for view_setup grouping columns -- no more
            # acronym/enabled, membership is <role-rater> itself now.
            cur.execute(
                "select pr.id, pr.user_id, u.login_name as name "
                "from project_rater pr "
                "join app_user u on u.id = pr.user_id "
                "where pr.project_id = %s order by u.login_name",
                (project["id"],),
            )
            raters = cur.fetchall()
            # FIX507.2.2.1.14.1: per rating-value usage breakdown, so
            # <table-rating-values>'s delete-confirmation popup can list
            # "{user} assigned this rating to {n} items." for every rating
            # value that already has assignments.
            cur.execute(
                "select ir.rating_value_id, u.login_name as name, count(*) as count "
                "from item_rating ir "
                "join folder f on f.id = ir.folder_id "
                "join app_user u on u.id = ir.user_id "
                "where f.project_id = %s "
                "group by ir.rating_value_id, u.login_name "
                "order by ir.rating_value_id, u.login_name",
                (project["id"],),
            )
            rating_value_usage = cur.fetchall()
            # FIX520.4.3: the displayed rating is ONLY the logged-in
            # caller's own -- never fetched/returned for anonymous
            # callers or for any other user.
            my_ratings_by_folder = {}
            if user is not None:
                cur.execute(
                    "select ir.folder_id, ir.rating_value_id "
                    "from item_rating ir "
                    "join folder f on f.id = ir.folder_id "
                    "where f.project_id = %s and ir.user_id = %s",
                    (project["id"], user["id"]),
                )
                my_ratings_by_folder = {
                    r["folder_id"]: r["rating_value_id"] for r in cur.fetchall()
                }
            # FIX504.2.1.2.2.6: unlike my_ratings_by_folder above, this is
            # every configured rater's rating (keyed by user_id), not just
            # the caller's own -- feeds the per-rater list columns, which
            # any admin/manager viewing the list can see regardless of who
            # is logged in.
            cur.execute(
                "select ir.folder_id, ir.user_id, ir.rating_value_id "
                "from item_rating ir "
                "join folder f on f.id = ir.folder_id "
                "where f.project_id = %s",
                (project["id"],),
            )
            ratings_by_folder = {}
            for r in cur.fetchall():
                ratings_by_folder.setdefault(r["folder_id"], {})[str(r["user_id"])] = r["rating_value_id"]
            # FIX520.4.7 <rating-conflict-detection>: only computed when
            # show_rating_conflict is on.
            conflict_folder_ids = set()
            if project.get("show_rating_conflict") and ratings_by_folder:
                cur.execute(
                    "select id, sort_order from rating_value where project_id = %s",
                    (project["id"],),
                )
                rank_by_value_id = {r["id"]: r["sort_order"] + 1 for r in cur.fetchall()}
                threshold = project.get("rating_conflict_threshold") or 3
                comparator = project.get("rating_conflict_comparator") or '<'
                conflict_folder_ids = _compute_conflict_folder_ids(
                    ratings_by_folder, rank_by_value_id, threshold, comparator,
                )
    folders = [
        {
            "id": r["id"],
            "name": r["name"],
            "note": r["note"],
            "sort_order": r["sort_order"],
            "properties": r["properties"] or {},
            # FIX525.3.5 <action-item-flagging>.
            "is_flagged": bool(r["is_flagged"]),
            "main_image_url": (
                public_image_url(r["main_storage_key"], r["main_created_at"])
                if r["main_storage_key"] else None
            ),
            # FIX511.4.1: the Item Gallery panel displays this instead of
            # main_image_url. May not exist for images uploaded before
            # FIX371.6.2.1/FIX670.20.4 -- the frontend falls back to
            # main_image_url on load error rather than backfilling here.
            "main_image_thumb_url": (
                thumbnail_url(r["main_storage_key"], r["main_thumb_created_at"])
                if r["main_storage_key"] else None
            ),
            "main_rotation": r["main_rotation"],
            "has_image": bool(r["has_image"]),
            # FIX504.2.1.2.2.4 <Image size>: sum of this item's image bytes.
            "image_bytes": int(r["image_bytes"] or 0),
            # FIX521.5.8.0 <item-img-zoom-factor>: stored item Zoom Factor.
            "zoom_factor": r["zoom_factor"],
            # FIX520.2.7 / FIX520.4.3 <icon-rating>: null when the caller
            # has no rating entered for this item (FIX520.4.4 hides it).
            "my_rating_value_id": my_ratings_by_folder.get(r["id"]),
            # FIX504.2.1.2.2.6: every rater's rating of this item, keyed by
            # user_id (string, since JSON object keys can't be a uuid).
            "ratings_by_user": ratings_by_folder.get(r["id"], {}),
            # FIX520.4.7 / FIX520.4.8 <item-with-conflicting-rating>.
            "has_rating_conflict": r["id"] in conflict_folder_ids,
        }
        for r in rows
    ]
    return {
        "project": {
            "id": project["id"],
            "name": project["name"],
            # FIX404.1.1: gates the item deep-link (only public projects).
            "is_public": bool(project.get("is_public")),
            "is_admin_or_manager": is_admin_or_manager,
            # FIX300.3.10.3.2 / FIX300.3.10.6.2 <role-layout-mngr> /
            # <role-setup-mngr> — gate <button-item-grouping>/
            # <button-columns> and <button-setup> respectively.
            "is_layout_mngr": is_layout_mngr,
            "is_setup_mngr": is_setup_mngr,
            # FIX352.2.6 / FIX503.3.5: surface the introduction so the
            # ShowcaseView About popup can render it. front_introduction
            # is intentionally NOT included here — it's a HomeView
            # concern (FIX352.2.5).
            "introduction": project.get("introduction") or "",
            # FIX352.2.7 + FIX503.2.13 + FIX503.2.20.1 <project-title>:
            # decorative label rendered in the project page header.
            "title_long_text": project.get("title_long_text") or "",
            "title_short_text": project.get("title_short_text") or "",
            "title_size": project.get("title_size"),
            "title_colour": project.get("title_colour"),
            "title_is_bold": bool(project.get("title_is_bold")),
        },
        "properties": properties,
        "view_setup": project["view_setup"] or {},
        "folders": folders,
        # FIX507.2.1 / FIX507.2.2 / FIX507.2.3 <panel-rating-setup>.
        "rating_setup": {
            "enabled": bool(project.get("enable_rating")),
            "values": rating_values,
            "raters": raters,
            # FIX507.2.4 / FIX507.2.5.
            "show_conflict": bool(project.get("show_rating_conflict")),
            "conflict_threshold": project.get("rating_conflict_threshold") or 3,
            # FIX507.2.6 <field-rating-conflict-comparator>.
            "conflict_comparator": project.get("rating_conflict_comparator") or '<',
            # FIX507.2.2.1.14.1.
            "value_usage": rating_value_usage,
        },
    }


# Bug fix (property_pkey collision, reported live on project 'Livres
# anciens' / id 1: UniqueViolation, Key (id)=(26) already exists).
# property.id is a single GLOBAL primary key, but the project-local id
# allocation (FIX350.2.2.2.1.1's project_id*1000+N scheme, so id % 1000
# shows a clean small display number) only stays collision-free for a
# project actually migrated into that band. Several early projects
# (this one included) still carry small legacy ids (11, 12, ... 25)
# predating the scheme -- a project-scoped max+1 there can land on a
# number some OTHER project already owns globally, which is exactly what
# happened (both independently computed 26). Falling back to the true
# global max+1 whenever it's higher than the project-scoped candidate
# keeps the pretty per-project numbering for every project already living
# in its own 1000+N band (its own max already IS the global high-water
# mark there) while guaranteeing no collision for a legacy project, at
# the cost of its next id occasionally jumping out of that project's
# usual-looking range.
def _next_property_id(cur, project_id):
    cur.execute(
        "select "
        "  coalesce((select max(p.id) from property p join folder f on f.id = p.master_folder_id "
        "            where f.project_id = %s), %s * 1000) as project_scoped, "
        "  coalesce((select max(id) from property), 0) as global_max",
        (project_id, project_id),
    )
    row = cur.fetchone()
    return max(row["project_scoped"], row["global_max"]) + 1


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
    # FIX401.2: setup writes are scoped to the caller's current
    # project. The frontend passes project_id alongside the
    # properties/view_setup payload; old clients that omit it still
    # get the first-in-panel-order project so single-project setups
    # don't break.
    payload_project_id = payload.get("project_id")
    incoming_props = payload.get("properties", [])
    view_setup = payload.get("view_setup", {}) or {}

    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            if payload_project_id is not None:
                cur.execute(
                    "select id from project where id = %s",
                    (payload_project_id,),
                )
            else:
                cur.execute(
                    "select id from project order by sort_order, id limit 1"
                )
            project = cur.fetchone()
            if not project:
                raise HTTPException(status_code=404, detail="no project")
            project_id = project["id"]

            # FIX507.4.2: <panel-rating-setup> is saved as part of this
            # same general setup save function, not a separate endpoint.
            # Callers that don't touch the Rating tab omit "rating"
            # entirely, leaving the existing DB state untouched.
            rating_payload = payload.get("rating")
            # FIX507.4.6: None when the Rating tab wasn't touched at all --
            # distinct from an empty list, so the caller can tell "nothing
            # to reassess" from "reassessed, nothing conflicts".
            conflicting_folder_ids = None
            if rating_payload is not None:
                cur.execute(
                    "update project set enable_rating = %s where id = %s",
                    (bool(rating_payload.get("enabled")), project_id),
                )
                # FIX507.2.5.1: mandatory, defaulted to 3 -- an invalid or
                # missing value falls back to the default rather than
                # blocking the whole save.
                try:
                    conflict_threshold = int(rating_payload.get("conflict_threshold"))
                except (TypeError, ValueError):
                    conflict_threshold = 3
                # FIX507.2.6: mandatory dropdown, defaulted to '<' -- any
                # other incoming value falls back to the default too.
                conflict_comparator = rating_payload.get("conflict_comparator")
                if conflict_comparator not in ('<', '>'):
                    conflict_comparator = '<'
                cur.execute(
                    "update project set show_rating_conflict = %s, "
                    "rating_conflict_threshold = %s, "
                    "rating_conflict_comparator = %s where id = %s",
                    (
                        bool(rating_payload.get("show_conflict")),
                        conflict_threshold,
                        conflict_comparator,
                        project_id,
                    ),
                )
                # FIX507.2.2.1 <table-rating-values>: same insert/update/
                # delete-by-diff pattern as the property table above.
                incoming_values = rating_payload.get("values") or []
                cur.execute(
                    "select id from rating_value where project_id = %s",
                    (project_id,),
                )
                existing_value_ids = {r["id"] for r in cur.fetchall()}
                incoming_value_ids = {
                    v["id"] for v in incoming_values if isinstance(v.get("id"), int)
                }
                for idx, v in enumerate(incoming_values):
                    text = (v.get("text") or "").strip()
                    if not text:
                        continue
                    icon = v.get("icon") or None
                    sort_order = v.get("sort_order", idx)
                    if isinstance(v.get("id"), int) and v["id"] in existing_value_ids:
                        cur.execute(
                            "update rating_value set text = %s, icon = %s, "
                            "sort_order = %s where id = %s",
                            (text, icon, sort_order, v["id"]),
                        )
                    else:
                        cur.execute(
                            "insert into rating_value "
                            "(project_id, text, icon, sort_order) "
                            "values (%s, %s, %s, %s)",
                            (project_id, text, icon, sort_order),
                        )
                values_to_delete = existing_value_ids - incoming_value_ids
                if values_to_delete:
                    cur.execute(
                        "delete from rating_value where id = any(%s)",
                        (list(values_to_delete),),
                    )

                # FIX507.4.6: changing <table-rating-values>,
                # <field-rating-conflict-threshold>, or
                # <field-rating-conflict-comparator> can change which
                # items conflict -- reassess every item now (deleting a
                # value above already cascades to remove its item_rating
                # rows, so this reads post-delete state) instead of
                # leaving stale has_rating_conflict flags until the next
                # full reload.
                cur.execute(
                    "select ir.folder_id, ir.user_id, ir.rating_value_id "
                    "from item_rating ir join folder f on f.id = ir.folder_id "
                    "where f.project_id = %s",
                    (project_id,),
                )
                save_ratings_by_folder = {}
                for r in cur.fetchall():
                    save_ratings_by_folder.setdefault(r["folder_id"], {})[str(r["user_id"])] = r["rating_value_id"]
                conflicting_folder_ids = []
                if bool(rating_payload.get("show_conflict")) and save_ratings_by_folder:
                    cur.execute(
                        "select id, sort_order from rating_value where project_id = %s",
                        (project_id,),
                    )
                    save_rank_by_value_id = {r["id"]: r["sort_order"] + 1 for r in cur.fetchall()}
                    conflicting_folder_ids = sorted(_compute_conflict_folder_ids(
                        save_ratings_by_folder, save_rank_by_value_id,
                        conflict_threshold, conflict_comparator,
                    ))

                # FIX507.2.3(removed): raters are no longer saved from
                # here -- <role-rater> (project_access.is_rater) is set
                # via <panel-project> (FIX352.3.10.10 / FIX351.2.1.8)
                # like every other role, and takes effect immediately.

                # FIX373.5.1 (Topic 6, User's basket): a single grouping,
                # named 'My basket', added/removed as field-enable-rating
                # or table-rating-values changes. Its property_id ('rating')
                # is the logged-in user's own rating -- the existing
                # generic bucketing (FIX374) already fans one property out
                # into one bucket per distinct value, so no per-value
                # sub-groups are needed (superseded FIX373.5.1(old)).
                basket_showcase_cfg = view_setup.get("showcase") or {}
                existing_groups = list(basket_showcase_cfg.get("groups") or [])
                existing_rating_group = next(
                    (g for g in existing_groups if g.get("property_id") == "rating"), None,
                )
                other_groups = [g for g in existing_groups if g.get("property_id") != "rating"]
                basket_group = []
                if rating_payload.get("enabled"):
                    # Preserve an already-existing group as-is (the admin
                    # may have renamed it or ticked Default) -- only a
                    # fresh add on the disabled->enabled transition gets
                    # the hardcoded default shape.
                    basket_group.append(existing_rating_group or {
                        "id": "g-rating",
                        "name": "My basket",
                        "property_id": "rating",
                        "segment": None,
                        "default": False,
                    })
                basket_showcase_cfg["groups"] = other_groups + basket_group
                view_setup["showcase"] = basket_showcase_cfg

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
                # Self-heal: legacy projects created before the
                # create_admin_project fix have no root folder. Create
                # one now (mirrors migration 005 backfill) so Setup save
                # works without the user having to run SQL.
                cur.execute(
                    "insert into folder (project_id, name, sort_order, is_master) "
                    "select id, name, 0, true from project where id = %s "
                    "returning id",
                    (project_id,),
                )
                master = cur.fetchone()
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
                    # FIX350.2.2.2.1.1 / .1.1.1: allocate a project-local
                    # id of the form project_id*1000 + N (see
                    # _next_property_id for the global-collision fallback).
                    next_id = _next_property_id(cur, project_id)
                    cur.execute(
                        "insert into property "
                        "  (id, master_folder_id, label, short_label, formula, "
                        "   trailing_values, accepted_value_set, sort_order) "
                        "values (%s, %s, %s, %s, %s, %s, %s, %s) returning id",
                        (
                            next_id,
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

            cur.execute(
                "select enable_rating, show_rating_conflict, rating_conflict_threshold, "
                "       rating_conflict_comparator "
                "from project where id = %s", (project_id,),
            )
            proj_row = cur.fetchone()
            enable_rating = bool(proj_row["enable_rating"])
            # Bug fix: same missing sort_order as get_showcase's own query.
            cur.execute(
                "select id, text, icon, sort_order from rating_value "
                "where project_id = %s order by sort_order, id",
                (project_id,),
            )
            fresh_rating_values = cur.fetchall()
            cur.execute(
                "select pr.id, pr.user_id, u.login_name as name "
                "from project_rater pr "
                "join app_user u on u.id = pr.user_id "
                "where pr.project_id = %s order by u.login_name",
                (project_id,),
            )
            fresh_raters = cur.fetchall()
            # FIX507.2.2.1.14.1: see the matching query in get_showcase.
            cur.execute(
                "select ir.rating_value_id, u.login_name as name, count(*) as count "
                "from item_rating ir "
                "join folder f on f.id = ir.folder_id "
                "join app_user u on u.id = ir.user_id "
                "where f.project_id = %s "
                "group by ir.rating_value_id, u.login_name "
                "order by ir.rating_value_id, u.login_name",
                (project_id,),
            )
            fresh_rating_value_usage = cur.fetchall()
        conn.commit()
    return {
        "properties": fresh_properties,
        "view_setup": view_setup,
        "rating_setup": {
            "enabled": enable_rating,
            "values": fresh_rating_values,
            "raters": fresh_raters,
            "show_conflict": bool(proj_row["show_rating_conflict"]),
            "conflict_threshold": proj_row["rating_conflict_threshold"] or 3,
            "conflict_comparator": proj_row["rating_conflict_comparator"] or '<',
            "value_usage": fresh_rating_value_usage,
        },
        # FIX507.4.6: None when the Rating tab wasn't touched (nothing to
        # reassess); otherwise every folder_id that now conflicts, so the
        # caller can update has_rating_conflict for the whole project
        # without a full reload.
        "conflicting_folder_ids": conflicting_folder_ids,
    }


# ============================================================
# FIX520.2.7 / FIX520.3.4 / FIX520.4.3-5: item rating -- a logged-in
# user's own rating of one item. Deliberately separate from
# _save_setup_impl above (admin-managed rating *configuration*, i.e.
# FIX507): this write comes from any logged-in visitor viewing the
# Showcase, not from the admin Setup popup.
# ============================================================
@app.post("/api/folders/{folder_id}/rating")
async def set_item_rating(
    folder_id: int,
    request: Request,
    user=Depends(current_user_required),
):
    """FIX520.3.4 sets or (rating_value_id: null, the '0' key) clears the
    caller's own rating for this item. FIX520.4.5: applied immediately,
    no separate save step. Requires the item's project to have rating
    enabled and the caller to be an enabled rater on it (FIX507.2.1 /
    FIX507.2.3.1.3)."""
    payload = await request.json()
    rating_value_id = payload.get("rating_value_id")
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select f.project_id, p.enable_rating "
                "from folder f join project p on p.id = f.project_id "
                "where f.id = %s",
                (folder_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="item not found")
            if not row["enable_rating"]:
                raise HTTPException(status_code=403, detail="rating is not enabled for this project")
            cur.execute(
                "select 1 from project_access "
                "where project_id = %s and user_id = %s and is_rater",
                (row["project_id"], user["id"]),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=403, detail="not a rater on this project")
            if rating_value_id is None:
                cur.execute(
                    "delete from item_rating where folder_id = %s and user_id = %s",
                    (folder_id, user["id"]),
                )
            else:
                cur.execute(
                    "select 1 from rating_value where id = %s and project_id = %s",
                    (rating_value_id, row["project_id"]),
                )
                if not cur.fetchone():
                    raise HTTPException(status_code=400, detail="unknown rating_value_id")
                cur.execute(
                    "insert into item_rating (folder_id, user_id, rating_value_id) "
                    "values (%s, %s, %s) "
                    "on conflict (folder_id, user_id) "
                    "do update set rating_value_id = excluded.rating_value_id",
                    (folder_id, user["id"], rating_value_id),
                )
        conn.commit()
    return {"folder_id": folder_id, "rating_value_id": rating_value_id}


@app.post("/api/folders/{folder_id}/flag")
async def set_item_flag(
    folder_id: int,
    request: Request,
    user=Depends(current_user_required),
):
    """FIX525.3.5 / <action-item-flagging>: sets or clears the small red
    'needs fixing' flag on an item. FIX525.3.5.2: only an Admin or a project
    Data Manager (<project-data-mngrs>) may do this -- same admin-exempt
    is_data_manager check /api/showcase uses to compute is_admin_or_manager.
    Visible to any viewer once set; only the write is gated."""
    payload = await request.json()
    flagged = bool(payload.get("flagged"))
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select project_id from folder where id = %s",
                (folder_id,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="item not found")
            cur.execute(
                "select is_admin from app_user where id = %s",
                (user["id"],),
            )
            pr = cur.fetchone()
            caller_is_admin = bool(pr and pr["is_admin"])
            if not caller_is_admin:
                cur.execute(
                    "select 1 from project_access "
                    "where project_id = %s and user_id = %s and is_data_manager",
                    (row["project_id"], user["id"]),
                )
                if not cur.fetchone():
                    raise HTTPException(status_code=403, detail="not a data manager on this project")
            cur.execute(
                "update folder set is_flagged = %s where id = %s",
                (flagged, folder_id),
            )
        conn.commit()
    return {"folder_id": folder_id, "is_flagged": flagged}


# ============================================================
# FIX370 / FIX370.0 <cmd-import-google-sheet>: Google Sheet import — one
# transactional endpoint
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
      "folder_renames": [{"id": 42, "name": "F003"}],
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
    folder_renames = payload.get("folder_renames") or []
    updates = payload.get("updates") or []

    try:
        return _apply_gsheet_plan(
            project_id, new_properties, renames, new_folders, folder_renames, updates
        )
    except HTTPException:
        raise
    except Exception as e:
        # Surface the actual error to the frontend instead of a bare 500 so
        # the import dialog can show something actionable.
        tb = traceback.format_exc()
        print("import-gsheet failed:\n" + tb, flush=True)
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")


def _apply_gsheet_plan(project_id, new_properties, renames, new_folders, folder_renames, updates):
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
                # FIX350.2.2.2.1.1 / .1.1.1: project-local id allocation
                # (see _next_property_id for the global-collision fallback).
                next_id = _next_property_id(cur, project_id)
                cur.execute(
                    "insert into property (id, master_folder_id, label, short_label, sort_order) "
                    "values (%s, %s, %s, %s, %s) returning id",
                    (next_id, master_folder_id, label, short_label, next_sort),
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

            # 2b) folder renames (FIX370.2.1.7) — rename an existing item's
            # '#' (folder.name) before the name_to_folder lookup (step 4) is
            # built, so later updates resolve against the new name.
            for r in folder_renames:
                cur.execute(
                    "update folder set name = %s "
                    "where id = %s and project_id = %s",
                    (r["name"], r["id"], project_id),
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
            # Bug fix (user-reported: {#} caption placeholder never got a
            # value even after a clean re-import that showed it as read).
            # FIX350.2.3.3: a project can have SEVERAL Master Folders, but
            # this used to only look up properties under the ONE master
            # (order by id limit 1, same as master_folder_id above) chosen
            # for creating brand-new properties/folders in this same
            # request. A property living under a different master folder
            # (e.g. setup-item-key-property, added separately from Setup)
            # then never matched here -- every update for it was silently
            # skipped (see skipped_prop below), with nothing surfaced to
            # the caller. /api/showcase's own property list (the read side)
            # already unions all master folders for the project; match that
            # here too instead of the single arbitrarily-picked one.
            cur.execute(
                "select p.id, p.label from property p "
                "join folder f on f.id = p.master_folder_id "
                "where f.project_id = %s and f.is_master",
                (project_id,),
            )
            property_rows = cur.fetchall()
            label_to_prop = {r["label"]: r["id"] for r in property_rows}
            # Traced: two properties sharing the same label would make the
            # dict comprehension above silently keep only one of their ids —
            # every update sent under that label then routes to whichever id
            # happened to win, which could be the *wrong* property while
            # looking completely successful (no skip, no logged conflict).
            _by_label = {}
            for r in property_rows:
                _by_label.setdefault(r["label"], []).append(r["id"])
            for label, ids in _by_label.items():
                if len(ids) > 1:
                    print(f"import-gsheet: property label={label!r} is shared by ids {ids} — "
                          f"updates sent under this label will all route to id {label_to_prop[label]}, "
                          f"the others are unreachable", flush=True)
            cur.execute(
                "select id, name from folder where project_id = %s",
                (project_id,),
            )
            folder_rows = cur.fetchall()
            name_to_folder = {r["name"]: r["id"] for r in folder_rows}
            _by_name = {}
            for r in folder_rows:
                _by_name.setdefault(r["name"], []).append(r["id"])
            for name, ids in _by_name.items():
                if len(ids) > 1:
                    print(f"import-gsheet: folder name={name!r} is shared by ids {ids} — "
                          f"updates sent for this name will all route to id {name_to_folder[name]}, "
                          f"the others are unreachable", flush=True)

            # 5) aggregate and merge updates into folder.properties JSONB
            # Traced (temporary, for tracking down FIX370 import bugs): logs
            # every update the server can't resolve to a real folder/property,
            # plus any (folder, property) pair that receives more than one
            # value in this same batch — the second overwrites the first
            # silently otherwise, with nothing surfaced to the caller.
            per_folder = {}
            skipped_folder = 0
            skipped_prop = 0
            for u in updates:
                folder_name = u.get("folder_name")
                property_label = u.get("property_label")
                fid = name_to_folder.get(folder_name)
                pid = label_to_prop.get(property_label)
                if fid is None:
                    skipped_folder += 1
                    print(f"import-gsheet: skip update, unknown folder_name={folder_name!r} "
                          f"(property_label={property_label!r})", flush=True)
                    continue
                if pid is None:
                    skipped_prop += 1
                    print(f"import-gsheet: skip update, unknown property_label={property_label!r} "
                          f"(folder_name={folder_name!r})", flush=True)
                    continue
                folder_map = per_folder.setdefault(fid, {})
                if str(pid) in folder_map and folder_map[str(pid)] != (u.get("value", "") or ""):
                    print(f"import-gsheet: folder_name={folder_name!r} property_label={property_label!r} "
                          f"got two different values in this batch: {folder_map[str(pid)]!r} -> "
                          f"{u.get('value', '') or ''!r} (last one wins)", flush=True)
                folder_map[str(pid)] = u.get("value", "") or ""
            print(f"import-gsheet: {len(updates)} update entries received, "
                  f"{len(per_folder)} folders touched, {skipped_folder} skipped "
                  f"(unknown folder), {skipped_prop} skipped (unknown property)", flush=True)

            for fid, merge_map in per_folder.items():
                cur.execute(
                    "update folder set "
                    "properties = coalesce(properties, '{}'::jsonb) || %s::jsonb "
                    "where id = %s",
                    (json.dumps(merge_map), fid),
                )

        conn.commit()
    # FIX370.4.3.10.1: updated_folders_count must match the frontend
    # preview's 'Updated item' count -- per_folder alone over-counts (it
    # includes brand-new folders, which write every imported column
    # unconditionally and so always show up here too) and under-counts
    # (a folder whose only change is its ref, via folder_renames, never
    # gets a properties update and so never enters per_folder at all).
    # Mirrors the frontend's updatedItemRows: per_folder minus new folders,
    # union renamed folders.
    new_folder_id_set = set(new_folder_ids.values())
    renamed_folder_id_set = {r["id"] for r in folder_renames}
    updated_folder_id_set = (set(per_folder.keys()) - new_folder_id_set) | renamed_folder_id_set
    return {
        "new_properties_count": len(new_prop_ids),
        "renames_count": len(renames),
        "new_folders_count": len(new_folder_ids),
        "folder_renames_count": len(folder_renames),
        "updated_folders_count": len(updated_folder_id_set),
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
    """Return the total bytes consumed by all images linked to folders of this
    project, summed from the image table's stored byte size (`image.bytes`,
    recorded at upload/shrink and backfilled at the R2 migration).
    Returns: { bytes, image_count, missing_count }
      - bytes: sum of stored file sizes
      - image_count: distinct images linked to this project
      - missing_count: image rows with no recorded size (upload never
        completed, or not yet migrated)
    """
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                with proj_imgs as (
                    select distinct i.id as image_id, i.bytes
                      from image i
                      join folder_image fi on fi.image_id = i.id
                      join folder f       on f.id = fi.folder_id
                     where f.project_id = %s
                )
                select
                  coalesce(sum(bytes), 0) as bytes,
                  count(*) as image_count,
                  count(*) filter (where bytes is null) as missing_count
                from proj_imgs
                """,
                (project_id,),
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
    """Delete a single object from R2. A missing object is treated as success
    (already gone). Raises HTTPException on any other failure."""
    try:
        s3().delete_object(Bucket=R2_BUCKET, Key=storage_key)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Bucket delete error: {e}")


def _has_image_row(storage_key: str) -> bool:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select 1 from image where storage_key = %s limit 1",
                (storage_key,),
            )
            return cur.fetchone() is not None


@app.post("/api/images/sign-upload")
# No auth dependency: the local app's Publish flow has no login
# process and was 401ing here on every new image. ImportImagesDialog
# (website, admin-only) still gates via the UI's <button-edit>/admin
# check, not via a backend token — same posture as the rest of this file.
async def sign_upload(request: Request):
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
    # FIX371: refuse to hand out an upload URL for a key already backing a live
    # image — real updates go through replaces_image_id, not a silent overwrite.
    # An orphan object (no image row) is fine: the presigned PUT just overwrites it.
    # Unlike the S3 call below, this had no error handling at all -- a dead/stale
    # pool connection (e.g. Supabase's pgBouncer dropping an idle one) raised
    # straight through as a bare Starlette 500 with no detail, instead of a
    # clear 502 like every other DB-adjacent failure here.
    try:
        already_backed = _has_image_row(storage_key)
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=502, detail=f"Could not check storage_key: {e}")
    if already_backed:
        raise HTTPException(status_code=409, detail="storage_key already backs an image")
    # S3 presigned PUT. ContentType is intentionally NOT signed, so the client's
    # own Content-Type header is accepted (and stored) without a signature mismatch.
    print(f"[r2] sign-upload key={storage_key}", flush=True)
    try:
        signed_url = s3().generate_presigned_url(
            "put_object",
            Params={"Bucket": R2_BUCKET, "Key": storage_key},
            ExpiresIn=600,
        )
        print(f"[r2] sign-upload OK key={storage_key}", flush=True)
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=502, detail=f"Sign upload failed: {e}")
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


# ============================================================
# FIX521.3.5 <button-shrink-image-list>: replace an image's stored bytes
# with a client-shrunk version.
# ============================================================
@app.post("/api/images/{image_id}/replace-bytes")
async def replace_image_bytes(image_id: int, request: Request, user=Depends(current_user_required)):
    """FIX521.3.5.2: overwrite an image's stored bytes with a client-provided
    (shrunk) version. Writes a NEW versioned storage key — the public URL is
    served with an immutable 1-year cache, so reusing the old key would keep
    serving the old bytes — repoints the image row, then deletes the old object
    so the shrink actually frees storage. Returns the new url + byte size."""
    # Bug fix: an unhandled exception anywhere in this body (e.g. a bad/
    # truncated request body failing request.json(), a pool/DB error) fell
    # through to Starlette's default handler, which returned a bare 500 with
    # NO body -- reported live as an empty-body 500 (and, once, a client-side
    # ERR_CONTENT_LENGTH_MISMATCH) on a rotated-image publish, with nothing
    # useful in the app logs to diagnose it by. Same try/except-and-log
    # pattern already used by save_setup/import-gsheet/sign-upload above.
    # Bug fix: this early-exit checked SUPABASE_SERVICE_ROLE_KEY (needed by an
    # unrelated Supabase REST call elsewhere in this file) instead of the R2
    # credentials this endpoint's own upload_to_bucket()/s3() actually need —
    # a copy-paste of the wrong guard. s3() already raises the correct "R2
    # storage not configured" 503 off the right variables (R2_ENDPOINT/
    # R2_ACCESS_KEY_ID/R2_SECRET_ACCESS_KEY) the moment it's called; this
    # just fast-fails on the same condition before doing the DB round-trip.
    try:
        if not (R2_ENDPOINT and R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY):
            raise HTTPException(status_code=503, detail="R2 storage not configured")
        payload = await request.json()
        content_type = payload.get("content_type") or "image/jpeg"
        # FIX521.5.8.1 <img-zoom-factor>: shrinking changes the pixel dims, so the
        # client recomputes the image's ZF and sends it to be re-stored. Optional.
        zoom_factor = payload.get("zoom_factor")
        if zoom_factor is not None:
            try:
                zoom_factor = float(zoom_factor)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail="zoom_factor must be a number or null")
        try:
            raw = base64.b64decode(payload.get("data_base64") or "", validate=False)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"could not decode image data: {e}")
        if not raw:
            raise HTTPException(status_code=400, detail="empty image data")
        with pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("select storage_key from image where id = %s", (image_id,))
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=404, detail="image not found")
                old_key = row["storage_key"]
                # Versioned key so the immutable CDN cache of the old public URL is
                # bypassed. Small incrementing counter (_v1, _v2, ...); never stack —
                # strip any existing _v<n> before appending the next.
                last = old_key.rsplit("/", 1)[-1]
                if "." in last:
                    base, _, ext = old_key.rpartition(".")
                    dot_ext = "." + ext
                else:
                    base, dot_ext = old_key, ""
                m = re.search(r"_v(\d+)$", base)
                n = int(m.group(1)) + 1 if m else 1
                if m:
                    base = base[: m.start()]
                new_key = f"{base}_v{n}{dot_ext}"
                upload_to_bucket(new_key, raw, content_type)
                # FIX524.4.10.3: the old thumbnail (if any) was built from
                # bytes this call just replaced -- stale the moment the crop/
                # rotate is saved, so it's regenerated here under the new
                # key, same best-effort-non-fatal pattern as confirm_image.
                try:
                    _create_thumbnail(new_key)
                    thumb_created_at = datetime.now()
                except Exception as e:
                    print(f"[r2] thumbnail FAILED key={new_key}: {e}", flush=True)
                    thumb_created_at = None
                cur.execute(
                    "update image set storage_key = %s, zoom_factor = %s, bytes = %s, "
                    "thumb_created_at = %s where id = %s",
                    (new_key, zoom_factor, len(raw), thumb_created_at, image_id),
                )
            conn.commit()
        # Best-effort delete of the old object (after commit, so a delete failure
        # can't undo the repoint). This is what makes the shrink free storage.
        if old_key and old_key != new_key:
            try:
                _bucket_delete(old_key)
            except Exception:
                pass
            try:
                _bucket_delete(thumbnail_storage_key(old_key))
            except Exception:
                pass
        # FIX521.5.9 (updated): the caller needs the freshly regenerated
        # thumbnail too, not just the full-size url -- otherwise whichever
        # row is currently the item's Gallery-panel thumbnail keeps
        # pointing at the pre-edit thumbnail after a rotate/crop save or a
        # Shrink, until the next full reload re-derives it server-side.
        return {
            "storage_key": new_key,
            "url": public_image_url(new_key),
            "thumb_url": thumbnail_url(new_key, thumb_created_at),
            "bytes": len(raw),
        }
    except HTTPException:
        raise
    except Exception as e:
        tb = traceback.format_exc()
        print(f"replace_image_bytes failed (image_id={image_id}, bytes={len(raw) if 'raw' in locals() else '?'}):\n{tb}", flush=True)
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")


# ============================================================
# FIX521.5.8.0 / FIX521.5.8.1: store an item's Zoom Factor (max ZF of its
# images), recomputed client-side whenever its images change.
# ============================================================
@app.post("/api/folders/{folder_id}/zoom-factor")
async def set_folder_zoom_factor(folder_id: int, request: Request, user=Depends(current_user_required)):
    payload = await request.json()
    zf = payload.get("zoom_factor")
    if zf is not None:
        try:
            zf = float(zf)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="zoom_factor must be a number or null")
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute("update folder set zoom_factor = %s where id = %s", (zf, folder_id))
        conn.commit()
    return {"folder_id": folder_id, "zoom_factor": zf}


def _get_or_create_folder(cur, project_id, item_name):
    """FIX371.6.1 / FIX620.4.2.2: find the item's folder by name, or
    auto-create it (under the project's Master Folder, blank properties)
    when the name isn't known yet. Shared by /api/images/confirm (upload
    already in hand) and /api/folders (bare creation, for staging)."""
    cur.execute(
        "select id from folder where project_id = %s and name = %s",
        (project_id, item_name),
    )
    row = cur.fetchone()
    if row:
        return row["id"]
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
    return cur.fetchone()["id"]


@app.post("/api/folders")
async def create_folder(request: Request):
    """FIX620.4.2.2: bare item creation (no image) — lets the client stage
    a captured photo locally (status 'Added') against a real item before
    any upload happens, same posture as /api/images/sign-upload (no auth
    dependency; local app has no login)."""
    payload = await request.json()
    project_id = payload.get("project_id")
    name = (payload.get("name") or "").strip()
    if not project_id or not name:
        raise HTTPException(status_code=400, detail="project_id, name required")
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            folder_id = _get_or_create_folder(cur, project_id, name)
        conn.commit()
    return {"id": folder_id, "name": name}


# FIX652.2.2 <cmd-publish-changes>: applies a pending Ref swap (FIX657) to a
# real item once <cmd-publish-changes> processes its
# <file-flag-chged-item-ref>-tagged staging folder. Rejects a collision with
# another item's Ref in the same project -- same check confirmNewItemRef
# already runs client-side, kept here too since this is the point the DB
# actually changes.
@app.patch("/api/folders/{folder_id}")
async def rename_folder(
    folder_id: int,
    request: Request,
    user=Depends(current_user_required),
):
    payload = await request.json()
    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select project_id from folder where id = %s", (folder_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="folder not found")
            cur.execute(
                "select 1 from folder where project_id = %s and id != %s and name = %s",
                (row["project_id"], folder_id, name),
            )
            if cur.fetchone():
                raise HTTPException(status_code=409, detail=f"Ref {name} is already in use")
            cur.execute("update folder set name = %s where id = %s", (name, folder_id))
        conn.commit()
    return {"id": folder_id, "name": name}


# FIX652.2.1 <cmd-publish-changes>: deletes an item's folder together with
# every image exclusively attached to it (bucket objects included) --
# processes a <file-flag-removed-item>-tagged staging folder (FIX658).
@app.delete("/api/folders/{folder_id}")
async def delete_folder(
    folder_id: int,
    user=Depends(current_user_required),
):
    storage_keys_to_drop = []
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("select id from folder where id = %s", (folder_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="folder not found")
            cur.execute(
                "select image_id from folder_image where folder_id = %s",
                (folder_id,),
            )
            image_ids = [r["image_id"] for r in cur.fetchall()]
            cur.execute("delete from folder_image where folder_id = %s", (folder_id,))
            for image_id in image_ids:
                cur.execute(
                    "select 1 from folder_image where image_id = %s limit 1",
                    (image_id,),
                )
                if cur.fetchone() is not None:
                    continue  # still used by another folder
                cur.execute("select storage_key from image where id = %s", (image_id,))
                img = cur.fetchone()
                if img:
                    storage_keys_to_drop.append(img["storage_key"])
                    cur.execute("delete from image where id = %s", (image_id,))
            cur.execute("delete from folder where id = %s", (folder_id,))
        conn.commit()
    # Same posture as delete_folder_image: drop bucket objects after the DB
    # commit so a transient bucket error never leaves a half-removed row.
    for key in storage_keys_to_drop:
        try:
            _bucket_delete(key)
        except HTTPException as e:
            print(f"delete_folder: bucket cleanup failed for {key}: {e.detail}", flush=True)
    return {"deleted": True, "images_deleted": len(storage_keys_to_drop)}


@app.post("/api/images/confirm")
async def confirm_image(request: Request):
    payload = await request.json()
    project_id = payload.get("project_id")
    item_name = (payload.get("item_name") or "").strip()
    storage_key = payload.get("storage_key")
    sort_order = payload.get("sort_order", 0)
    caption = payload.get("caption")
    replaces_image_id = payload.get("replaces_image_id")
    # FIX371.6.3 / FIX521.5.8.1 <img-zoom-factor>: the client computes the
    # image's ZF from its pixel dims (against the Reference Viewport) and sends
    # it here so it's stored on the image row at creation. Optional / nullable.
    zoom_factor = payload.get("zoom_factor")
    if zoom_factor is not None:
        try:
            zoom_factor = float(zoom_factor)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="zoom_factor must be a number or null")
    if not project_id or not item_name or not storage_key:
        raise HTTPException(status_code=400, detail="project_id, item_name, storage_key required")

    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            folder_id = _get_or_create_folder(cur, project_id, item_name)

            # Record the stored byte size (read from R2) so the size stats
            # don't depend on the storage backend's own metadata tables.
            try:
                head = s3().head_object(Bucket=R2_BUCKET, Key=storage_key)
                obj_bytes = int(head.get("ContentLength") or 0)
                print(f"[r2] confirm head key={storage_key} bytes={obj_bytes}", flush=True)
            except Exception as e:
                print(f"[r2] confirm head FAILED key={storage_key}: {e}", flush=True)
                obj_bytes = None

            # FIX371.6.2.1 (hard-disk import) / FIX670.20.4 (local-app
            # publication): both flows call this same endpoint, so creating
            # the thumbnail here covers both in one place. Best-effort --
            # a thumbnail failure must not fail the image upload itself, and
            # leaves thumb_created_at NULL so the startup backfill retries
            # it later instead of this row being silently stuck without one.
            try:
                _create_thumbnail(storage_key)
                thumb_created_at = datetime.now()
            except Exception as e:
                print(f"[r2] thumbnail FAILED key={storage_key}: {e}", flush=True)
                thumb_created_at = None

            cur.execute(
                "insert into image (storage_key, zoom_factor, bytes, thumb_created_at) "
                "values (%s, %s, %s, %s) returning id",
                (storage_key, zoom_factor, obj_bytes, thumb_created_at),
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
                  img.crop,
                  img.zoom_factor,
                  img.thumb_created_at,
                  img.created_at
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
            "url": public_image_url(r["storage_key"], r["created_at"]),
            # Same field the Item Gallery's main_image_thumb_url uses
            # (/api/showcase) -- lets the editor push a freshly-set main
            # image straight into the gallery's cache without a refetch.
            "thumb_url": thumbnail_url(r["storage_key"], r["thumb_created_at"]),
            "rotation": r["rotation"],
            "crop": r["crop"],
            # FIX521.5.8.1 <img-zoom-factor>: stored per-image Zoom Factor.
            "zoom_factor": r["zoom_factor"],
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

    sort_order_changed = "sort_order" in payload
    with pool.connection() as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "select id, folder_id, image_id from folder_image where id = %s",
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

            # FIX521.5.9: the item's thumbnail (main_image_thumb_url, which
            # always resolves to whichever image is main or -- lacking a
            # main -- first by sort_order) must actually have one generated
            # once it becomes that image, in case it predates the
            # FIX371.6.2.1/FIX670.20.4 backfill or a prior thumbnail attempt
            # failed. Best-effort, same posture as confirm_image's own
            # thumbnail generation -- must not fail this PATCH.
            image_id_to_check = None
            if set_is_main_true:
                image_id_to_check = existing["image_id"]
            elif sort_order_changed and not row["is_main"]:
                cur.execute(
                    "select 1 from folder_image where folder_id = %s and is_main = true limit 1",
                    (existing["folder_id"],),
                )
                if not cur.fetchone():
                    cur.execute(
                        "select image_id from folder_image where folder_id = %s "
                        "order by sort_order, id limit 1",
                        (existing["folder_id"],),
                    )
                    first = cur.fetchone()
                    if first and first["image_id"] == existing["image_id"]:
                        image_id_to_check = existing["image_id"]
            if image_id_to_check is not None:
                cur.execute(
                    "select storage_key, thumb_created_at from image where id = %s",
                    (image_id_to_check,),
                )
                img = cur.fetchone()
                if img and img["thumb_created_at"] is None:
                    try:
                        _create_thumbnail(img["storage_key"])
                        cur.execute(
                            "update image set thumb_created_at = now() where id = %s",
                            (image_id_to_check,),
                        )
                    except Exception as e:
                        print(f"[folder-image] FIX521.5.9 thumbnail FAILED image_id={image_id_to_check}: {e}", flush=True)
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


# FIX524.4.10 non-destructive save: update crop rectangle and/or rotation
# on the Image row. The physical asset in
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
