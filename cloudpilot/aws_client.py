"""AWS client helpers — session management, region discovery, org tree."""
import boto3
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional


DEFAULT_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
]


def get_session(profile=None, region=None):
    kwargs = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.Session(**kwargs)


def get_client(service, region=None, profile=None):
    return get_session(profile, region).client(service)


def get_regions(region=None, profile=None):
    if region:
        return [region]
    try:
        ec2 = get_client("ec2", profile=profile, region="us-east-1")
        resp = ec2.describe_regions(Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])
        return [r["RegionName"] for r in resp["Regions"]]
    except Exception:
        return DEFAULT_REGIONS


def get_account_id(profile=None):
    sts = get_client("sts", profile=profile)
    return sts.get_caller_identity()["Account"]


def parallel_regions(fn, regions, profile=None, max_workers=10):
    """Run fn across regions in parallel, return aggregated results.
    Supports fn(region, profile) or fn(region) signatures."""
    import inspect
    # Detect if fn accepts 2+ positional args (region, profile)
    try:
        sig = inspect.signature(fn)
        params = [p for p in sig.parameters.values()
                  if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
        takes_profile = len(params) >= 2
    except (ValueError, TypeError):
        takes_profile = True  # default to passing profile

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        if takes_profile:
            futures = {pool.submit(fn, r, profile): r for r in regions}
        else:
            futures = {pool.submit(fn, r): r for r in regions}
        for f in as_completed(futures):
            try:
                result = f.result()
                if isinstance(result, list):
                    results.extend(result)
                elif result is not None:
                    results.append(result)
            except Exception:
                pass
    return results


def build_org_tree(profile=None):
    """Build org tree: list of {account_id, name, ou_path, status}."""
    orgs = get_client("organizations", profile=profile, region="us-east-1")
    accounts = []
    paginator = orgs.get_paginator("list_accounts")
    for page in paginator.paginate():
        for acct in page["Accounts"]:
            if acct["Status"] == "ACTIVE":
                accounts.append({
                    "account_id": acct["Id"],
                    "name": acct.get("Name", ""),
                    "email": acct.get("Email", ""),
                    "status": acct["Status"],
                })
    return accounts


def assume_role_session(account_id, role_name, profile=None, region=None):
    sts = get_client("sts", profile=profile)
    resp = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
        RoleSessionName="cloudpilot-scan",
    )
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region or "us-east-1",
    )
