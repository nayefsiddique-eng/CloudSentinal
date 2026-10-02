import os
from datetime import datetime, timezone
from functools import lru_cache

import boto3
from dotenv import load_dotenv

load_dotenv(override=False)


def get_session():
    """Use AWS's standard credential chain. Never require hard-coded keys."""
    profile = os.getenv("AWS_PROFILE") or None
    return boto3.Session(profile_name=profile) if profile else boto3.Session()


def get_client(service_name: str, region: str | None = None):
    session = get_session()
    selected_region = region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or session.region_name or "us-east-1"
    return session.client(service_name, region_name=selected_region)


def get_account_context():
    sts = get_client("sts", region="us-east-1")
    identity = sts.get_caller_identity()
    return {
        "account_id": identity["Account"],
        "arn": identity.get("Arn"),
        "user_id": identity.get("UserId"),
        "now": datetime.now(timezone.utc),
    }


def validate_credentials():
    return get_account_context()


@lru_cache(maxsize=1)
def get_regions():
    """Return enabled EC2 regions. Falls back to the configured region."""
    configured = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
    try:
        ec2 = get_client("ec2", region=configured or "us-east-1")
        result = ec2.describe_regions(AllRegions=False)
        regions = sorted({r["RegionName"] for r in result.get("Regions", [])})
        if regions:
            return regions
    except Exception:
        pass
    return [configured or "us-east-1"]
