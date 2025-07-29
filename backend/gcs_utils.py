from google.cloud import storage
import os
from datetime import timedelta

BUCKET_NAME = "secure-file-storage-bucket"

def upload_to_gcs(file_path, filename):
    client = storage.Client()
    bucket = client.bucket(BUCKET_NAME)
    blob = bucket.blob(filename)
    blob.upload_from_filename(file_path)

def download_from_gcs(filename, local_path):
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(BUCKET_NAME)
    blob = bucket.blob(filename)
    
    # Download file to the local path
    blob.download_to_filename(local_path)


def generate_signed_url(filename, expiration_minutes=15):
    client = storage.Client()
    bucket = client.bucket(BUCKET_NAME)
    blob = bucket.blob(filename)

    # Generate a signed URL for the encrypted file (valid for 15 minutes)
    url = blob.generate_signed_url(expiration=timedelta(minutes=expiration_minutes), method='GET')
    return url