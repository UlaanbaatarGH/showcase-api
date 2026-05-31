#!/usr/bin/env python3
"""Set the R2 bucket CORS policy so the browser can PUT uploads and read images
back for canvas (Shrink) operations. Idempotent — re-running overwrites.

Env: R2_ENDPOINT, R2_BUCKET, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY
"""
import os
import boto3
from botocore.config import Config
from dotenv import load_dotenv

load_dotenv()

s3 = boto3.client(
    "s3",
    endpoint_url=os.environ["R2_ENDPOINT"],
    aws_access_key_id=os.environ["R2_ACCESS_KEY_ID"],
    aws_secret_access_key=os.environ["R2_SECRET_ACCESS_KEY"],
    region_name="auto",
    config=Config(signature_version="s3v4"),
)
bucket = os.environ.get("R2_BUCKET", "showcase-images")
origins = [
    "https://showcase.x22.fr",
    "https://showcase-omega-jade.vercel.app",
    "http://localhost:5173",
    "http://localhost:5174",
]
s3.put_bucket_cors(
    Bucket=bucket,
    CORSConfiguration={
        "CORSRules": [
            {
                "AllowedOrigins": origins,
                "AllowedMethods": ["GET", "PUT", "HEAD"],
                "AllowedHeaders": ["*"],
                "ExposeHeaders": ["ETag"],
                "MaxAgeSeconds": 3600,
            }
        ]
    },
)
print("CORS set on", bucket)
for rule in s3.get_bucket_cors(Bucket=bucket)["CORSRules"]:
    print(" ", rule["AllowedMethods"], rule["AllowedOrigins"])
