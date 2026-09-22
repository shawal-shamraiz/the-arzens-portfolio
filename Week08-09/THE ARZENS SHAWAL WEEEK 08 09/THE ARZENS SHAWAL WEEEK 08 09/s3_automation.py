"""
s3_automation.py
-----------------
Simple S3 automation script for Week 08-09 assignment (Task 2).

Requires:
    pip install boto3
    aws configure      (enter your AWS Access Key, Secret Key, and default region)

Usage examples (run from a terminal):
    python s3_automation.py list-buckets
    python s3_automation.py create-bucket my-new-bucket-name
    python s3_automation.py upload my-bucket-name path/to/file.txt
    python s3_automation.py list-files my-bucket-name
"""

import sys
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def get_client():
    """Create a boto3 S3 client. Centralized so every function shares one setup."""
    return boto3.client("s3")


def list_buckets():
    """Show all S3 buckets in the connected AWS account."""
    try:
        s3 = get_client()
        response = s3.list_buckets()
        buckets = response.get("Buckets", [])
        if not buckets:
            print("No buckets found in this account.")
            return
        print(f"Found {len(buckets)} bucket(s):")
        for bucket in buckets:
            print(f"  - {bucket['Name']} (created {bucket['CreationDate']})")
    except NoCredentialsError:
        print("AWS credentials not found. Run 'aws configure' first.")
    except ClientError as e:
        print(f"Could not list buckets: {e.response['Error']['Message']}")


def create_bucket(name, region=None):
    """Create a new S3 bucket with the given name."""
    try:
        s3 = get_client()
        if region and region != "us-east-1":
            s3.create_bucket(
                Bucket=name,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        else:
            s3.create_bucket(Bucket=name)
        print(f"Created bucket: {name}")
    except NoCredentialsError:
        print("AWS credentials not found. Run 'aws configure' first.")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "BucketAlreadyExists" or code == "BucketAlreadyOwnedByYou":
            print(f"Bucket '{name}' already exists. Try a different, globally unique name.")
        else:
            print(f"Could not create bucket: {e.response['Error']['Message']}")


def upload_file(bucket, file_path, object_name=None):
    """Upload a local file to the given bucket."""
    if object_name is None:
        object_name = file_path.split("/")[-1]
    try:
        s3 = get_client()
        s3.upload_file(file_path, bucket, object_name)
        print(f"Uploaded '{file_path}' to bucket '{bucket}' as '{object_name}'.")
    except FileNotFoundError:
        print(f"Local file not found: {file_path}")
    except NoCredentialsError:
        print("AWS credentials not found. Run 'aws configure' first.")
    except ClientError as e:
        print(f"Upload failed: {e.response['Error']['Message']}")


def list_files(bucket):
    """Show all files (objects) inside a bucket."""
    try:
        s3 = get_client()
        response = s3.list_objects_v2(Bucket=bucket)
        contents = response.get("Contents", [])
        if not contents:
            print(f"Bucket '{bucket}' is empty (or does not exist).")
            return
        print(f"Files in '{bucket}':")
        for obj in contents:
            size_kb = obj["Size"] / 1024
            print(f"  - {obj['Key']} ({size_kb:.1f} KB)")
    except NoCredentialsError:
        print("AWS credentials not found. Run 'aws configure' first.")
    except ClientError as e:
        print(f"Could not list files: {e.response['Error']['Message']}")


def print_usage():
    print(__doc__)


if __name__ == "__main__":
    args = sys.argv[1:]

    if not args:
        list_buckets()  # default action matches the assignment's sample code
        sys.exit(0)

    command = args[0]

    if command == "list-buckets":
        list_buckets()
    elif command == "create-bucket" and len(args) >= 2:
        create_bucket(args[1])
    elif command == "upload" and len(args) >= 3:
        upload_file(args[1], args[2])
    elif command == "list-files" and len(args) >= 2:
        list_files(args[1])
    else:
        print("Unknown or incomplete command.\n")
        print_usage()
