# S3 Automation Script — Setup & Usage

## What this is
A simple Python script (`s3_automation.py`) that automates basic Amazon S3
operations: listing buckets, creating a bucket, uploading a file, and listing
the files inside a bucket.

## Prerequisites
1. An AWS account (the [AWS Free Tier](https://aws.amazon.com/free) covers this — free for 12 months).
2. Python 3.8+ installed.
3. The AWS CLI installed ([aws.amazon.com/cli](https://aws.amazon.com/cli)).

## Setup Steps

1. **Install dependencies**
   ```bash
   pip install boto3
   ```

2. **Create an IAM user with limited permissions (least privilege)**
   - In the AWS Console, go to IAM → Users → Create user.
   - Attach only the `AmazonS3FullAccess` policy (or a custom policy scoped to
     just the bucket(s) you need — even better for least privilege).
   - Generate an Access Key ID and Secret Access Key for this user.

3. **Configure your credentials locally**
   ```bash
   aws configure
   ```
   You'll be prompted for:
   - AWS Access Key ID
   - AWS Secret Access Key
   - Default region (e.g. `us-east-1`)
   - Default output format (e.g. `json`)

4. **Run the script**
   ```bash
   # List all buckets in your account
   python s3_automation.py list-buckets

   # Create a new bucket (bucket names must be globally unique)
   python s3_automation.py create-bucket my-unique-bucket-name-2026

   # Upload a file to a bucket
   python s3_automation.py upload my-unique-bucket-name-2026 ./notes.txt

   # List the files inside a bucket
   python s3_automation.py list-files my-unique-bucket-name-2026
   ```

5. **Take your screenshot**
   Run any of the commands above against your own AWS account and screenshot
   the terminal output (or the AWS S3 console showing the result) as
   `screenshot.png` — this proves the script actually works against a real
   account. This step needs to be done on your machine since it requires your
   own AWS credentials.

## Notes on Security
- Never commit your AWS Access Key / Secret Key to Git. Keep them only in
  your local AWS CLI config (`~/.aws/credentials`), which this script reads
  automatically.
- The IAM user used here should only have the permissions it needs (S3
  access), not full admin access — this is the "least privilege" principle
  covered in Task 1.
