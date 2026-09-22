"""
ec2_manager.py
--------------
Simple EC2 instance manager for Week 08-09 assignment (Task 3).

Requires:
    pip install boto3
    aws configure

Usage examples (run from a terminal):
    python ec2_manager.py list
    python ec2_manager.py start i-0123456789abcdef0
    python ec2_manager.py stop i-0123456789abcdef0
"""

import sys
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from config import AWS_REGION


def get_resource():
    """Create a boto3 EC2 resource using the region from config.py."""
    return boto3.resource("ec2", region_name=AWS_REGION)


def list_instances():
    """Show all EC2 instances as a simple table: ID, State, Type, IP."""
    try:
        ec2 = get_resource()
        instances = list(ec2.instances.all())

        if not instances:
            print("No EC2 instances found in this region.")
            return

        print(f"{'Instance ID':<22}{'State':<12}{'Type':<12}{'Public IP':<15}")
        print("-" * 61)
        for instance in instances:
            ip = instance.public_ip_address or "N/A"
            print(f"{instance.id:<22}{instance.state['Name']:<12}{instance.instance_type:<12}{ip:<15}")
    except NoCredentialsError:
        print("AWS credentials not found. Run 'aws configure' first.")
    except ClientError as e:
        print(f"Could not list instances: {e.response['Error']['Message']}")


def _confirm(action, instance_id):
    """Simple safety check before starting/stopping an instance."""
    answer = input(f"Are you sure you want to {action} instance {instance_id}? (yes/no): ")
    return answer.strip().lower() in ("yes", "y")


def start_instance(instance_id):
    """Start a stopped EC2 instance, after confirmation."""
    if not _confirm("START", instance_id):
        print("Cancelled.")
        return
    try:
        ec2 = get_resource()
        instance = ec2.Instance(instance_id)
        instance.start()
        print(f"Starting instance {instance_id}... (state changes may take a minute)")
    except NoCredentialsError:
        print("AWS credentials not found. Run 'aws configure' first.")
    except ClientError as e:
        print(f"Could not start instance: {e.response['Error']['Message']}")


def stop_instance(instance_id):
    """Stop a running EC2 instance, after confirmation."""
    if not _confirm("STOP", instance_id):
        print("Cancelled.")
        return
    try:
        ec2 = get_resource()
        instance = ec2.Instance(instance_id)
        instance.stop()
        print(f"Stopping instance {instance_id}... (state changes may take a minute)")
    except NoCredentialsError:
        print("AWS credentials not found. Run 'aws configure' first.")
    except ClientError as e:
        print(f"Could not stop instance: {e.response['Error']['Message']}")


def print_usage():
    print(__doc__)


if __name__ == "__main__":
    args = sys.argv[1:]

    if not args:
        list_instances()
        sys.exit(0)

    command = args[0]

    if command == "list":
        list_instances()
    elif command == "start" and len(args) >= 2:
        start_instance(args[1])
    elif command == "stop" and len(args) >= 2:
        stop_instance(args[1])
    else:
        print("Unknown or incomplete command.\n")
        print_usage()
