#!/usr/bin/env python3
"""One-time migration: copy image objects from Supabase Storage to Cloudflare R2
under IDENTICAL keys, and backfill the `image.bytes` size column.

Non-destructive: it only READS from Supabase and WRITES to R2 + the DB size
column. The Supabase bucket is left intact (delete it later, after cutover, to
reclaim space). Safe to re-run — re-uploading the same key just overwrites.

Bytes stream directly Supabase -> R2 in this process; nothing is printed except
counts/sizes.

Env (from .env / environment):
  DATABASE_URL, SUPABASE_URL, SUPABASE_BUCKET, [SUPABASE_SERVICE_ROLE_KEY],
  R2_ENDPOINT, R2_BUCKET, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY

Usage:
  python scripts/migrate_to_r2.py                 # migrate everything
  python scripts/migrate_to_r2.py --skip-existing # skip keys already in R2 (by size)
  python scripts/migrate_to_r2.py --dry-run       # list what would move, no writes
"""
import os
import sys
import mimetypes
import urllib.request
import urllib.error

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]
SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SUPABASE_BUCKET = os.environ.get("SUPABASE_BUCKET", "showcase-images")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
R2_ENDPOINT = os.environ["R2_ENDPOINT"]
R2_BUCKET = os.environ.get("R2_BUCKET", "showcase-images")
R2_ACCESS_KEY_ID = os.environ["R2_ACCESS_KEY_ID"]
R2_SECRET_ACCESS_KEY = os.environ["R2_SECRET_ACCESS_KEY"]

SKIP_EXISTING = "--skip-existing" in sys.argv
DRY_RUN = "--dry-run" in sys.argv

s3 = boto3.client(
    "s3",
    endpoint_url=R2_ENDPOINT,
    aws_access_key_id=R2_ACCESS_KEY_ID,
    aws_secret_access_key=R2_SECRET_ACCESS_KEY,
    region_name="auto",
    config=Config(signature_version="s3v4"),
)


def download(key: str) -> bytes:
    """Fetch an object's bytes from Supabase Storage. Tries the public URL
    first; falls back to the authenticated endpoint if a service key is set."""
    public = f"{SUPABASE_URL}/storage/v1/object/public/{SUPABASE_BUCKET}/{key}"
    try:
        with urllib.request.urlopen(public, timeout=60) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code not in (400, 401, 403, 404) or not SUPABASE_SERVICE_ROLE_KEY:
            raise
    auth = f"{SUPABASE_URL}/storage/v1/object/{SUPABASE_BUCKET}/{key}"
    req = urllib.request.Request(
        auth,
        headers={
            "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
        },
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def r2_size(key: str):
    try:
        return int(s3.head_object(Bucket=R2_BUCKET, Key=key).get("ContentLength") or 0)
    except ClientError:
        return None


def collect_keys(conn):
    """Returns (image_keys, cover_keys). image_keys = [(image_id, key)],
    cover_keys = [key] (project covers, not tracked in the image table)."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("select id, storage_key from image where storage_key is not null")
        image_keys = [(r["id"], r["storage_key"]) for r in cur.fetchall()]
        cur.execute(
            "select distinct cover_image_key from project "
            "where cover_image_key is not null and cover_image_key <> ''"
        )
        cover_keys = [r["cover_image_key"] for r in cur.fetchall()]
    return image_keys, cover_keys


def main():
    conn = psycopg.connect(DATABASE_URL, autocommit=True)

    # Ensure the size column exists (idempotent).
    if not DRY_RUN:
        with conn.cursor() as cur:
            cur.execute("alter table image add column if not exists bytes bigint")

    image_keys, cover_keys = collect_keys(conn)
    print(f"To migrate: {len(image_keys)} image objects + {len(cover_keys)} cover objects")

    total_bytes = 0
    done = skipped = failed = 0

    def migrate(key, image_id=None):
        nonlocal total_bytes, done, skipped, failed
        if SKIP_EXISTING:
            existing = r2_size(key)
            if existing:
                if image_id is not None and not DRY_RUN:
                    with conn.cursor() as cur:
                        cur.execute(
                            "update image set bytes = %s where id = %s and bytes is null",
                            (existing, image_id),
                        )
                skipped += 1
                return
        if DRY_RUN:
            print(f"  would copy {key}")
            done += 1
            return
        try:
            data = download(key)
        except Exception as e:
            failed += 1
            print(f"  FAILED download {key}: {e}")
            return
        ctype = mimetypes.guess_type(key)[0] or "application/octet-stream"
        try:
            s3.put_object(
                Bucket=R2_BUCKET,
                Key=key,
                Body=data,
                ContentType=ctype,
                CacheControl="public, max-age=31536000, immutable",
            )
        except Exception as e:
            failed += 1
            print(f"  FAILED upload {key}: {e}")
            return
        size = len(data)
        total_bytes += size
        if image_id is not None:
            with conn.cursor() as cur:
                cur.execute("update image set bytes = %s where id = %s", (size, image_id))
        done += 1
        if done % 25 == 0:
            print(f"  ... {done} copied ({total_bytes/1_048_576:.1f} MB)")

    for image_id, key in image_keys:
        migrate(key, image_id)
    for key in cover_keys:
        migrate(key)

    conn.close()
    print(
        f"Done. copied={done} skipped={skipped} failed={failed} "
        f"total={total_bytes/1_048_576:.1f} MB"
    )
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
