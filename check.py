#!/usr/bin/env python3
"""
Cloud Penetration Testing - Day 1 Role Enumeration Script
Enumerates top 5 most-used roles in AWS and Azure using read-only credentials.

AWS: Requires ReadOnlyAccess or SecurityAudit policy
Azure: Requires Reader role at subscription level

Usage:
  AWS:   python3 enumerate_top_roles.py --provider aws [--profile <profile>] [--region <region>]
  Azure: python3 enumerate_top_roles.py --provider azure [--subscription <sub-id>]
"""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime

# ─────────────────────────────────────────────────────────────────
# ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="CPT Day-1 Role Enumeration Script (AWS & Azure)"
    )
    parser.add_argument("--provider", choices=["aws", "azure"], required=True,
                        help="Cloud provider to enumerate")

    # AWS-specific
    parser.add_argument("--profile", default=None,
                        help="[AWS] Named boto3/CLI profile to use")
    parser.add_argument("--region", default="us-east-1",
                        help="[AWS] Region for EC2/STS calls (default: us-east-1)")
    parser.add_argument("--access-key", default=None,
                        help="[AWS] AWS_ACCESS_KEY_ID (overrides profile/env)")
    parser.add_argument("--secret-key", default=None,
                        help="[AWS] AWS_SECRET_ACCESS_KEY (overrides profile/env)")
    parser.add_argument("--session-token", default=None,
                        help="[AWS] AWS_SESSION_TOKEN (for temp credentials)")

    # Azure-specific
    parser.add_argument("--subscription", default=None,
                        help="[Azure] Subscription ID to enumerate")

    parser.add_argument("--top", type=int, default=5,
                        help="Number of top roles to return (default: 5)")
    parser.add_argument("--output", choices=["text", "json"], default="text",
                        help="Output format")
    parser.add_argument("--save", default=None,
                        help="Save output to file path")
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────
# AWS ENUMERATION
# ─────────────────────────────────────────────────────────────────

def aws_get_session(args):
    try:
        import boto3
    except ImportError:
        print("[ERROR] boto3 not installed. Run: pip install boto3")
        sys.exit(1)

    kwargs = {}
    if args.access_key and args.secret_key:
        kwargs["aws_access_key_id"] = args.access_key
        kwargs["aws_secret_access_key"] = args.secret_key
        if args.session_token:
            kwargs["aws_session_token"] = args.session_token
        session = boto3.Session(**kwargs)
    elif args.profile:
        session = boto3.Session(profile_name=args.profile)
    else:
        session = boto3.Session()

    return session


def aws_enumerate_iam_user_roles(iam_client, top_n):
    """
    Enumerate IAM roles directly attached to users (via inline + managed policies)
    and roles assigned to groups the users belong to.
    Returns a Counter of role/policy ARNs and their usage counts.
    """
    print("\n[*] Enumerating IAM users and their directly attached roles/policies...")
    role_counter = Counter()
    role_details = {}

    paginator = iam_client.get_paginator("list_users")
    users = []
    for page in paginator.paginate():
        users.extend(page["Users"])
    print(f"    Found {len(users)} IAM users")

    # Per-user attached managed policies
    for user in users:
        username = user["UserName"]
        try:
            pol_pag = iam_client.get_paginator("list_attached_user_policies")
            for page in pol_pag.paginate(UserName=username):
                for pol in page["AttachedPolicies"]:
                    arn = pol["PolicyArn"]
                    role_counter[arn] += 1
                    if arn not in role_details:
                        role_details[arn] = {
                            "name": pol["PolicyName"],
                            "arn": arn,
                            "type": "ManagedPolicy",
                            "permissions_summary": []
                        }
        except Exception as e:
            print(f"    [WARN] Could not list policies for user {username}: {e}")

        # Inline user policies
        try:
            inline_pag = iam_client.get_paginator("list_user_policies")
            for page in inline_pag.paginate(UserName=username):
                for pol_name in page["PolicyNames"]:
                    key = f"inline:user:{username}:{pol_name}"
                    role_counter[key] += 1
                    if key not in role_details:
                        role_details[key] = {
                            "name": pol_name,
                            "arn": key,
                            "type": "InlineUserPolicy",
                            "permissions_summary": []
                        }
        except Exception as e:
            print(f"    [WARN] Could not list inline policies for user {username}: {e}")

    # Group memberships → group policies
    print("[*] Enumerating IAM group policies...")
    group_paginator = iam_client.get_paginator("list_groups")
    groups = []
    for page in group_paginator.paginate():
        groups.extend(page["Groups"])
    print(f"    Found {len(groups)} IAM groups")

    for group in groups:
        gname = group["GroupName"]
        try:
            # Members count
            members_resp = iam_client.get_group(GroupName=gname)
            member_count = len(members_resp.get("Users", []))

            gpol_pag = iam_client.get_paginator("list_attached_group_policies")
            for page in gpol_pag.paginate(GroupName=gname):
                for pol in page["AttachedPolicies"]:
                    arn = pol["PolicyArn"]
                    role_counter[arn] += member_count  # each member effectively gets this
                    if arn not in role_details:
                        role_details[arn] = {
                            "name": pol["PolicyName"],
                            "arn": arn,
                            "type": "ManagedPolicy (via Group)",
                            "permissions_summary": []
                        }
        except Exception as e:
            print(f"    [WARN] Could not enumerate group {gname}: {e}")

    return role_counter, role_details


def aws_enumerate_instance_profile_roles(iam_client, top_n):
    """
    Enumerate EC2 instance profile roles and how many instances use each.
    Returns a Counter of role ARNs and their usage counts.
    """
    print("\n[*] Enumerating EC2 instance profile roles...")
    role_counter = Counter()
    role_details = {}

    # Get all instance profiles
    ip_paginator = iam_client.get_paginator("list_instance_profiles")
    profiles = []
    for page in ip_paginator.paginate():
        profiles.extend(page["InstanceProfiles"])
    print(f"    Found {len(profiles)} instance profiles")

    for profile in profiles:
        for role in profile.get("Roles", []):
            arn = role["Arn"]
            role_counter[arn] += 1
            if arn not in role_details:
                role_details[arn] = {
                    "name": role["RoleName"],
                    "arn": arn,
                    "type": "EC2 Instance Profile Role",
                    "permissions_summary": []
                }

    return role_counter, role_details


def aws_get_policy_permissions(iam_client, policy_arn, role_details):
    """Fetch the policy document and summarize key permissions."""
    if not policy_arn.startswith("arn:aws"):
        return  # Skip inline policy keys

    try:
        policy = iam_client.get_policy(PolicyArn=policy_arn)
        version_id = policy["Policy"]["DefaultVersionId"]
        version = iam_client.get_policy_version(
            PolicyArn=policy_arn, VersionId=version_id
        )
        statements = version["PolicyVersion"]["Document"].get("Statement", [])

        summary = []
        for stmt in statements:
            effect = stmt.get("Effect", "Allow")
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            # Flag dangerous permissions
            dangerous = [a for a in actions if any(
                keyword in a.lower() for keyword in
                ["*", "iam:", "sts:assumerole", "s3:*", "ec2:*", "lambda:",
                 "secretsmanager:", "ssm:", "kms:", "cloudformation:", "iam:passrole"]
            )]

            summary.append({
                "Effect": effect,
                "Actions": actions[:10],  # Limit for readability
                "Resources": resources[:5],
                "DangerousPermissions": dangerous[:10]
            })

        role_details[policy_arn]["permissions_summary"] = summary
        role_details[policy_arn]["full_document"] = version["PolicyVersion"]["Document"]

    except Exception as e:
        role_details.get(policy_arn, {})["permissions_summary"] = [
            {"error": str(e)}
        ]


def enumerate_aws(args):
    session = aws_get_session(args)
    iam = session.client("iam")

    # Validate access
    print("\n[*] Validating AWS credentials...")
    try:
        sts = session.client("sts", region_name=args.region)
        identity = sts.get_caller_identity()
        print(f"    Account:  {identity['Account']}")
        print(f"    User/Role: {identity['Arn']}")
    except Exception as e:
        print(f"[ERROR] Could not validate credentials: {e}")
        sys.exit(1)

    # IAM user/group roles
    user_role_counter, user_role_details = aws_enumerate_iam_user_roles(iam, args.top)

    # Instance profile roles
    ip_role_counter, ip_role_details = aws_enumerate_instance_profile_roles(iam, args.top)

    # Combine details dicts
    all_role_details = {**user_role_details, **ip_role_details}

    # Get top N for each category
    top_user_roles = user_role_counter.most_common(args.top)
    top_ip_roles = ip_role_counter.most_common(args.top)

    # Fetch permissions for top roles
    print(f"\n[*] Fetching permissions for top {args.top} user/group roles...")
    for arn, _ in top_user_roles:
        aws_get_policy_permissions(iam, arn, all_role_details)

    print(f"[*] Fetching permissions for top {args.top} instance profile roles...")
    for arn, _ in top_ip_roles:
        aws_get_policy_permissions(iam, arn, all_role_details)

    return {
        "provider": "AWS",
        "account": identity["Account"],
        "enumerated_at": datetime.utcnow().isoformat() + "Z",
        "top_user_group_roles": [
            {**all_role_details.get(arn, {"arn": arn}), "usage_count": count}
            for arn, count in top_user_roles
        ],
        "top_instance_profile_roles": [
            {**all_role_details.get(arn, {"arn": arn}), "usage_count": count}
            for arn, count in top_ip_roles
        ],
        "recommendation": build_aws_recommendation(top_user_roles, top_ip_roles, all_role_details)
    }


def build_aws_recommendation(top_user_roles, top_ip_roles, details):
    recs = []
    if top_user_roles:
        most_used_arn, count = top_user_roles[0]
        d = details.get(most_used_arn, {})
        recs.append(f"Request IAM role/policy '{d.get('name', most_used_arn)}' for testing user access "
                    f"(assigned to {count} user(s)/group(s)).")
    if top_ip_roles:
        most_used_arn, count = top_ip_roles[0]
        d = details.get(most_used_arn, {})
        recs.append(f"Request EC2 instance with instance profile '{d.get('name', most_used_arn)}' attached "
                    f"(used by {count} instance profile(s)).")
    return recs


# ─────────────────────────────────────────────────────────────────
# AZURE ENUMERATION
# ─────────────────────────────────────────────────────────────────

def enumerate_azure(args):
    try:
        from azure.identity import DefaultAzureCredential, AzureCliCredential
        from azure.mgmt.authorization import AuthorizationManagementClient
        from azure.mgmt.resource import SubscriptionClient
    except ImportError:
        print("[ERROR] Azure SDK not installed. Run:")
        print("  pip install azure-identity azure-mgmt-authorization azure-mgmt-resource")
        sys.exit(1)

    print("\n[*] Authenticating to Azure (using DefaultAzureCredential)...")
    print("    Tries: environment vars → managed identity → Azure CLI → VS Code")

    try:
        credential = DefaultAzureCredential()
    except Exception as e:
        print(f"[ERROR] Authentication failed: {e}")
        sys.exit(1)

    # Resolve subscription
    if args.subscription:
        subscription_id = args.subscription
    else:
        print("[*] No subscription specified, discovering available subscriptions...")
        sub_client = SubscriptionClient(credential)
        subs = list(sub_client.subscriptions.list())
        if not subs:
            print("[ERROR] No subscriptions found.")
            sys.exit(1)
        if len(subs) == 1:
            subscription_id = subs[0].subscription_id
            print(f"    Using subscription: {subs[0].display_name} ({subscription_id})")
        else:
            print("    Available subscriptions:")
            for i, s in enumerate(subs):
                print(f"    [{i}] {s.display_name} ({s.subscription_id})")
            choice = int(input("    Select subscription index: "))
            subscription_id = subs[choice].subscription_id

    auth_client = AuthorizationManagementClient(credential, subscription_id)

    # List all role assignments
    print(f"\n[*] Fetching role assignments in subscription {subscription_id}...")
    assignments = list(auth_client.role_assignments.list_for_subscription())
    print(f"    Found {len(assignments)} role assignments")

    # Count by role definition ID
    role_counter = Counter()
    for assignment in assignments:
        role_counter[assignment.role_definition_id] += 1

    top_roles = role_counter.most_common(args.top)

    # Fetch role definitions
    print(f"\n[*] Fetching details for top {args.top} roles...")
    role_details = []
    for role_def_id, count in top_roles:
        try:
            # Extract the short role ID from the full path
            short_id = role_def_id.split("/")[-1]
            scope = f"/subscriptions/{subscription_id}"
            role_def = auth_client.role_definitions.get_by_id(role_def_id)

            # Summarize permissions
            permissions = []
            for perm in role_def.permissions:
                permissions.append({
                    "Actions": list(perm.actions or [])[:15],
                    "NotActions": list(perm.not_actions or [])[:5],
                    "DataActions": list(perm.data_actions or [])[:10],
                    "NotDataActions": list(perm.not_data_actions or [])[:5]
                })

                # Identify dangerous permissions
                dangerous = [a for a in (perm.actions or []) if
                             "*" in a or any(k in a.lower() for k in
                             ["microsoft.authorization/", "microsoft.keyvault/",
                              "microsoft.compute/virtualmachines/",
                              "microsoft.storage/storageaccounts/listkeys",
                              "microsoft.resources/subscriptions"])]

            role_details.append({
                "name": role_def.role_name,
                "id": role_def_id,
                "type": role_def.role_type,  # BuiltInRole or CustomRole
                "description": role_def.description,
                "usage_count": count,
                "permissions": permissions,
                "dangerous_permissions": dangerous[:10] if dangerous else []
            })
        except Exception as e:
            role_details.append({
                "id": role_def_id,
                "usage_count": count,
                "error": str(e)
            })

    # Build recommendation
    recommendation = []
    if role_details:
        top = role_details[0]
        recommendation.append(
            f"Request an Azure AD account with the '{top['name']}' role assigned "
            f"({top['usage_count']} assignments in this subscription)."
        )
        recommendation.append(
            "Also request a Kali Linux VM in the same subscription/resource group "
            "for interactive testing."
        )

    return {
        "provider": "Azure",
        "subscription_id": subscription_id,
        "enumerated_at": datetime.utcnow().isoformat() + "Z",
        "top_roles": role_details,
        "recommendation": recommendation
    }


# ─────────────────────────────────────────────────────────────────
# OUTPUT FORMATTING
# ─────────────────────────────────────────────────────────────────

def print_aws_results(results):
    print("\n" + "=" * 70)
    print("  AWS ROLE ENUMERATION RESULTS")
    print(f"  Account: {results['account']}")
    print(f"  Time:    {results['enumerated_at']}")
    print("=" * 70)

    print("\n┌─ TOP USER / GROUP ROLES ─────────────────────────────────────────┐")
    for i, role in enumerate(results["top_user_group_roles"], 1):
        print(f"\n  #{i} {role.get('name', role.get('arn', 'Unknown'))}")
        print(f"      ARN:        {role.get('arn', 'N/A')}")
        print(f"      Type:       {role.get('type', 'N/A')}")
        print(f"      Assigned:   {role['usage_count']} time(s)")
        perms = role.get("permissions_summary", [])
        if perms and "error" not in perms[0]:
            dangerous = []
            for stmt in perms:
                dangerous.extend(stmt.get("DangerousPermissions", []))
            if dangerous:
                print(f"      ⚠ HIGH-VALUE PERMISSIONS: {', '.join(set(dangerous[:5]))}")

    print("\n┌─ TOP INSTANCE PROFILE ROLES ─────────────────────────────────────┐")
    for i, role in enumerate(results["top_instance_profile_roles"], 1):
        print(f"\n  #{i} {role.get('name', role.get('arn', 'Unknown'))}")
        print(f"      ARN:        {role.get('arn', 'N/A')}")
        print(f"      Type:       {role.get('type', 'N/A')}")
        print(f"      Usage:      {role['usage_count']} instance profile(s)")
        perms = role.get("permissions_summary", [])
        if perms and "error" not in perms[0]:
            dangerous = []
            for stmt in perms:
                dangerous.extend(stmt.get("DangerousPermissions", []))
            if dangerous:
                print(f"      ⚠ HIGH-VALUE PERMISSIONS: {', '.join(set(dangerous[:5]))}")

    print("\n┌─ RECOMMENDATIONS ────────────────────────────────────────────────┐")
    for rec in results["recommendation"]:
        print(f"  → {rec}")
    print()


def print_azure_results(results):
    print("\n" + "=" * 70)
    print("  AZURE ROLE ENUMERATION RESULTS")
    print(f"  Subscription: {results['subscription_id']}")
    print(f"  Time:         {results['enumerated_at']}")
    print("=" * 70)

    print("\n┌─ TOP ASSIGNED ROLES ─────────────────────────────────────────────┐")
    for i, role in enumerate(results["top_roles"], 1):
        if "error" in role:
            print(f"\n  #{i} [Role fetch failed: {role['error']}]")
            continue
        print(f"\n  #{i} {role.get('name', 'Unknown')}")
        print(f"      Type:      {role.get('type', 'N/A')}")
        print(f"      Assigned:  {role['usage_count']} time(s)")
        print(f"      Desc:      {(role.get('description') or 'N/A')[:80]}")
        if role.get("dangerous_permissions"):
            print(f"      ⚠ HIGH-VALUE: {', '.join(role['dangerous_permissions'][:5])}")

    print("\n┌─ RECOMMENDATIONS ────────────────────────────────────────────────┐")
    for rec in results["recommendation"]:
        print(f"  → {rec}")
    print()


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    print("=" * 70)
    print("  CPT Day-1 Role Enumeration Script")
    print(f"  Provider: {args.provider.upper()}")
    print(f"  Top N:    {args.top}")
    print("=" * 70)

    if args.provider == "aws":
        results = enumerate_aws(args)
        if args.output == "json":
            output = json.dumps(results, indent=2, default=str)
            print(output)
        else:
            print_aws_results(results)
            output = json.dumps(results, indent=2, default=str)

    elif args.provider == "azure":
        results = enumerate_azure(args)
        if args.output == "json":
            output = json.dumps(results, indent=2, default=str)
            print(output)
        else:
            print_azure_results(results)
            output = json.dumps(results, indent=2, default=str)

    # Save output
    if args.save:
        with open(args.save, "w") as f:
            f.write(output)
        print(f"\n[*] Results saved to: {args.save}")
    else:
        # Auto-save JSON
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"cpt_role_enum_{args.provider}_{ts}.json"
        with open(filename, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[*] Full JSON results auto-saved to: {filename}")


if __name__ == "__main__":
    main()
