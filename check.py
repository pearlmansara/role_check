#!/usr/bin/env python3
"""
Cloud Penetration Testing - Day 1 Role Enumeration Script
Enumerates top N most-used roles/policies in AWS and Azure using read-only
credentials, and shows exactly which users/principals are assigned to each.

AWS: Requires ReadOnlyAccess or SecurityAudit policy
Azure: Requires Reader role at subscription level

Usage:
  AWS:   python3 enumerate_top_roles.py --provider aws [--profile <profile>] [--region <region>]
  Azure: python3 enumerate_top_roles.py --provider azure [--subscription <sub-id>]

Dependencies:
  AWS:   pip install boto3
  Azure: pip install azure-identity azure-mgmt-authorization azure-mgmt-resource requests
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
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
    parser.add_argument("--profile", default=None,
                        help="[AWS] Named boto3/CLI profile to use")
    parser.add_argument("--region", default="us-east-1",
                        help="[AWS] Region for STS/EC2 calls (default: us-east-1)")
    parser.add_argument("--access-key", default=None,
                        help="[AWS] AWS_ACCESS_KEY_ID (overrides profile/env)")
    parser.add_argument("--secret-key", default=None,
                        help="[AWS] AWS_SECRET_ACCESS_KEY (overrides profile/env)")
    parser.add_argument("--session-token", default=None,
                        help="[AWS] AWS_SESSION_TOKEN (for temporary credentials)")
    parser.add_argument("--subscription", default=None,
                        help="[Azure] Subscription ID to enumerate")
    parser.add_argument("--top", type=int, default=5,
                        help="Number of top roles to return (default: 5)")
    parser.add_argument("--output", choices=["text", "json"], default="text",
                        help="Output format")
    parser.add_argument("--save", default=None,
                        help="Save full JSON output to this file path")
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────
# AWS: SESSION
# ─────────────────────────────────────────────────────────────────

def aws_get_session(args):
    try:
        import boto3
    except ImportError:
        print("[ERROR] boto3 not installed. Run: pip install boto3")
        sys.exit(1)

    if args.access_key and args.secret_key:
        kwargs = {
            "aws_access_key_id": args.access_key,
            "aws_secret_access_key": args.secret_key,
        }
        if args.session_token:
            kwargs["aws_session_token"] = args.session_token
        return boto3.Session(**kwargs)
    elif args.profile:
        return boto3.Session(profile_name=args.profile)
    else:
        return boto3.Session()


# ─────────────────────────────────────────────────────────────────
# AWS: IAM USER/GROUP POLICY ENUMERATION
# ─────────────────────────────────────────────────────────────────

def aws_enumerate_iam_user_roles(iam_client):
    """
    Build a map of  policy_key -> { metadata, assigned_users[] }

    Covers:
      - Managed policies attached directly to IAM users
      - Inline policies attached directly to IAM users
      - Managed policies attached to IAM groups  (members resolved)
      - Inline policies attached to IAM groups   (members resolved)
    """
    print("\n[*] Enumerating IAM users...")
    all_users = []
    for page in iam_client.get_paginator("list_users").paginate():
        all_users.extend(page["Users"])
    print(f"    Found {len(all_users)} IAM users")

    policy_map = {}   # arn/key -> dict
    role_counter = Counter()

    # ── Direct per-user policy attachments ──────────────────────────────────
    for user in all_users:
        username = user["UserName"]
        user_arn = user["Arn"]

        # Managed policies directly on this user
        try:
            for page in iam_client.get_paginator("list_attached_user_policies").paginate(UserName=username):
                for pol in page["AttachedPolicies"]:
                    arn = pol["PolicyArn"]
                    role_counter[arn] += 1
                    if arn not in policy_map:
                        policy_map[arn] = {
                            "name": pol["PolicyName"],
                            "arn": arn,
                            "type": "ManagedPolicy",
                            "permissions_summary": [],
                            "assigned_users": []
                        }
                    policy_map[arn]["assigned_users"].append({
                        "username": username,
                        "user_arn": user_arn,
                        "source": "DirectUserAttachment"
                    })
        except Exception as e:
            print(f"    [WARN] Managed policies for {username}: {e}")

        # Inline policies directly on this user
        try:
            for page in iam_client.get_paginator("list_user_policies").paginate(UserName=username):
                for pol_name in page["PolicyNames"]:
                    key = f"inline:user:{username}:{pol_name}"
                    role_counter[key] += 1
                    if key not in policy_map:
                        policy_map[key] = {
                            "name": pol_name,
                            "arn": key,
                            "type": "InlineUserPolicy",
                            "permissions_summary": [],
                            "assigned_users": []
                        }
                    policy_map[key]["assigned_users"].append({
                        "username": username,
                        "user_arn": user_arn,
                        "source": "DirectInlinePolicy"
                    })
        except Exception as e:
            print(f"    [WARN] Inline policies for {username}: {e}")

    # ── Group memberships -> group policies -> member users ──────────────────
    print("[*] Enumerating IAM groups and resolving memberships...")
    all_groups = []
    for page in iam_client.get_paginator("list_groups").paginate():
        all_groups.extend(page["Groups"])
    print(f"    Found {len(all_groups)} IAM groups")

    for group in all_groups:
        gname = group["GroupName"]
        try:
            members = iam_client.get_group(GroupName=gname).get("Users", [])

            # Managed policies on the group
            for page in iam_client.get_paginator("list_attached_group_policies").paginate(GroupName=gname):
                for pol in page["AttachedPolicies"]:
                    arn = pol["PolicyArn"]
                    role_counter[arn] += len(members) if members else 1
                    if arn not in policy_map:
                        policy_map[arn] = {
                            "name": pol["PolicyName"],
                            "arn": arn,
                            "type": "ManagedPolicy (via Group)",
                            "permissions_summary": [],
                            "assigned_users": []
                        }
                    for m in members:
                        entry = {
                            "username": m["UserName"],
                            "user_arn": m["Arn"],
                            "source": f"GroupMembership:{gname}"
                        }
                        if entry not in policy_map[arn]["assigned_users"]:
                            policy_map[arn]["assigned_users"].append(entry)

            # Inline policies on the group
            for page in iam_client.get_paginator("list_group_policies").paginate(GroupName=gname):
                for pol_name in page["PolicyNames"]:
                    key = f"inline:group:{gname}:{pol_name}"
                    role_counter[key] += len(members) if members else 1
                    if key not in policy_map:
                        policy_map[key] = {
                            "name": pol_name,
                            "arn": key,
                            "type": "InlineGroupPolicy",
                            "permissions_summary": [],
                            "assigned_users": []
                        }
                    for m in members:
                        entry = {
                            "username": m["UserName"],
                            "user_arn": m["Arn"],
                            "source": f"GroupMembership:{gname}"
                        }
                        if entry not in policy_map[key]["assigned_users"]:
                            policy_map[key]["assigned_users"].append(entry)

        except Exception as e:
            print(f"    [WARN] Group {gname}: {e}")

    return role_counter, policy_map


# ─────────────────────────────────────────────────────────────────
# AWS: INSTANCE PROFILE ENUMERATION
# ─────────────────────────────────────────────────────────────────

def aws_enumerate_instance_profile_roles(iam_client, ec2_client):
    """
    Build a map of  role_arn -> { metadata, instance_profiles[], assigned_instances[] }

    Resolves actual running EC2 instances (ID + Name tag + state) for each role.
    """
    print("\n[*] Enumerating instance profiles...")
    all_profiles = []
    for page in iam_client.get_paginator("list_instance_profiles").paginate():
        all_profiles.extend(page["InstanceProfiles"])
    print(f"    Found {len(all_profiles)} instance profiles")

    role_map = {}
    for profile in all_profiles:
        for role in profile.get("Roles", []):
            role_arn = role["Arn"]
            if role_arn not in role_map:
                role_map[role_arn] = {
                    "name": role["RoleName"],
                    "arn": role_arn,
                    "type": "EC2 Instance Profile Role",
                    "permissions_summary": [],
                    "instance_profiles": [],
                    "assigned_instances": []
                }
            pname = profile["InstanceProfileName"]
            if pname not in role_map[role_arn]["instance_profiles"]:
                role_map[role_arn]["instance_profiles"].append(pname)

    # Build a lookup: profile_name -> role_arn
    profile_name_to_role = {}
    for role_arn, details in role_map.items():
        for pname in details["instance_profiles"]:
            profile_name_to_role[pname] = role_arn

    # Resolve actual EC2 instances
    print("[*] Resolving EC2 instances to instance profile roles...")
    try:
        for page in ec2_client.get_paginator("describe_instances").paginate():
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    iid   = inst["InstanceId"]
                    state = inst.get("State", {}).get("Name", "unknown")
                    name  = next(
                        (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                        "(no name)"
                    )
                    ip_assoc = inst.get("IamInstanceProfile")
                    if not ip_assoc:
                        continue
                    ip_arn = ip_assoc.get("Arn", "")
                    # Match profile name from the ARN suffix
                    matched_role = None
                    for pname, role_arn in profile_name_to_role.items():
                        if ip_arn.endswith(f"/{pname}") or f":{pname}" in ip_arn:
                            matched_role = role_arn
                            break
                    if matched_role:
                        entry = {
                            "instance_id": iid,
                            "name": name,
                            "state": state,
                            "instance_profile_arn": ip_arn
                        }
                        if entry not in role_map[matched_role]["assigned_instances"]:
                            role_map[matched_role]["assigned_instances"].append(entry)
    except Exception as e:
        print(f"    [WARN] EC2 describe_instances failed: {e}")

    # Weight counter: prefer actual instance count, fall back to profile count
    role_counter = Counter()
    for role_arn, details in role_map.items():
        ic = len(details["assigned_instances"])
        pc = len(details["instance_profiles"])
        role_counter[role_arn] = ic if ic > 0 else pc

    return role_counter, role_map


# ─────────────────────────────────────────────────────────────────
# AWS: POLICY PERMISSION LOOKUP
# ─────────────────────────────────────────────────────────────────

def aws_get_policy_permissions(iam_client, policy_key, role_details):
    """Fetch a managed policy document and flag dangerous permissions."""
    if not policy_key.startswith("arn:aws"):
        return  # Inline policy — no ARN to query

    try:
        version_id = iam_client.get_policy(PolicyArn=policy_key)["Policy"]["DefaultVersionId"]
        doc = iam_client.get_policy_version(
            PolicyArn=policy_key, VersionId=version_id
        )["PolicyVersion"]["Document"]

        summary = []
        for stmt in doc.get("Statement", []):
            effect    = stmt.get("Effect", "Allow")
            actions   = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            if isinstance(actions, str):   actions   = [actions]
            if isinstance(resources, str): resources = [resources]

            dangerous = [a for a in actions if any(
                kw in a.lower() for kw in [
                    "*", "iam:", "sts:assumerole", "s3:*", "ec2:*",
                    "lambda:", "secretsmanager:", "ssm:", "kms:",
                    "cloudformation:", "iam:passrole"
                ]
            )]
            summary.append({
                "Effect": effect,
                "Actions": actions[:10],
                "Resources": resources[:5],
                "DangerousPermissions": dangerous[:10]
            })

        role_details[policy_key]["permissions_summary"] = summary
        role_details[policy_key]["full_document"] = doc

    except Exception as e:
        if policy_key in role_details:
            role_details[policy_key]["permissions_summary"] = [{"error": str(e)}]


# ─────────────────────────────────────────────────────────────────
# AWS: ORCHESTRATION
# ─────────────────────────────────────────────────────────────────

def enumerate_aws(args):
    session = aws_get_session(args)
    iam     = session.client("iam")
    ec2     = session.client("ec2", region_name=args.region)

    print("\n[*] Validating AWS credentials...")
    try:
        identity = session.client("sts", region_name=args.region).get_caller_identity()
        print(f"    Account : {identity['Account']}")
        print(f"    Caller  : {identity['Arn']}")
    except Exception as e:
        print(f"[ERROR] Credential validation failed: {e}")
        sys.exit(1)

    user_counter, user_map = aws_enumerate_iam_user_roles(iam)
    ip_counter,   ip_map   = aws_enumerate_instance_profile_roles(iam, ec2)

    top_user = user_counter.most_common(args.top)
    top_ip   = ip_counter.most_common(args.top)

    print(f"\n[*] Fetching permissions for top {args.top} user/group policies...")
    for arn, _ in top_user:
        aws_get_policy_permissions(iam, arn, user_map)

    print(f"[*] Fetching permissions for top {args.top} instance profile roles...")
    for arn, _ in top_ip:
        aws_get_policy_permissions(iam, arn, ip_map)

    top_user_list = [
        {**user_map.get(a, {"arn": a}), "usage_count": c} for a, c in top_user
    ]
    top_ip_list = [
        {**ip_map.get(a, {"arn": a}), "usage_count": c} for a, c in top_ip
    ]

    return {
        "provider": "AWS",
        "account": identity["Account"],
        "caller_arn": identity["Arn"],
        "enumerated_at": datetime.utcnow().isoformat() + "Z",
        "top_user_group_roles": top_user_list,
        "top_instance_profile_roles": top_ip_list,
        "recommendation": _aws_recommendation(top_user_list, top_ip_list)
    }


def _aws_recommendation(top_user_list, top_ip_list):
    recs = []
    if top_user_list:
        r = top_user_list[0]
        users = r.get("assigned_users", [])
        sample = ", ".join(u["username"] for u in users[:3])
        recs.append(
            f"Request IAM policy '{r.get('name', r.get('arn'))}' — "
            f"assigned to {r['usage_count']} user(s)/group-member(s)"
            + (f" (e.g. {sample})" if sample else "") + "."
        )
    if top_ip_list:
        r = top_ip_list[0]
        instances = r.get("assigned_instances", [])
        sample = ", ".join(
            f"{i['instance_id']} ({i['name']})" for i in instances[:2]
        )
        recs.append(
            f"Request EC2 with instance profile role '{r.get('name', r.get('arn'))}' — "
            f"seen on {r['usage_count']} instance(s)"
            + (f" (e.g. {sample})" if sample else "") + "."
        )
    return recs


# ─────────────────────────────────────────────────────────────────
# AZURE: PRINCIPAL NAME RESOLUTION
# ─────────────────────────────────────────────────────────────────

def _resolve_azure_principals(credential, principal_ids, principal_id_map):
    """
    Batch-resolve Azure AD object IDs to display names via Microsoft Graph.
    Requires the token to have Directory.Read.All or User.Read.All.
    Reader alone may not have this — failures are handled gracefully and
    raw object IDs are used as the fallback display name.
    """
    if not principal_ids:
        return
    try:
        import requests
    except ImportError:
        print("    [WARN] 'requests' not installed — principal names will show as object IDs.")
        print("           Run: pip install requests")
        return

    try:
        token = credential.get_token("https://graph.microsoft.com/.default")
        headers = {
            "Authorization": f"Bearer {token.token}",
            "Content-Type": "application/json"
        }
        chunk_size = 20
        resolved = 0
        for i in range(0, len(principal_ids), chunk_size):
            chunk = principal_ids[i:i + chunk_size]
            resp = requests.post(
                "https://graph.microsoft.com/v1.0/directoryObjects/getByIds",
                headers=headers,
                json={"ids": chunk, "types": ["user", "group", "servicePrincipal"]},
                timeout=15
            )
            if resp.status_code != 200:
                print(f"    [WARN] Graph API returned HTTP {resp.status_code}. "
                      "Raw object IDs will be used (Reader role may lack Graph permissions).")
                break
            for obj in resp.json().get("value", []):
                oid = obj.get("id", "")
                odt = obj.get("@odata.type", "").lower()
                if "user" in odt:
                    principal_id_map[oid] = {
                        "display_name": obj.get("displayName") or obj.get("userPrincipalName", oid),
                        "upn": obj.get("userPrincipalName", ""),
                        "principal_type": "User"
                    }
                elif "group" in odt:
                    principal_id_map[oid] = {
                        "display_name": obj.get("displayName", oid),
                        "principal_type": "Group"
                    }
                elif "serviceprincipal" in odt:
                    principal_id_map[oid] = {
                        "display_name": obj.get("displayName", oid),
                        "principal_type": "ServicePrincipal"
                    }
                else:
                    principal_id_map[oid] = {
                        "display_name": obj.get("displayName", oid),
                        "principal_type": odt.split(".")[-1] if odt else "Unknown"
                    }
                resolved += 1

        print(f"    Resolved {resolved}/{len(principal_ids)} principal display names via Graph API")
    except Exception as e:
        print(f"    [WARN] Graph principal resolution failed: {e}")
        print("    Raw object IDs will be used as fallback display names.")


def _build_azure_principal_list(assignments, principal_id_map):
    principals = []
    for a in assignments:
        pid      = a.principal_id or ""
        resolved = principal_id_map.get(pid, {})
        scope    = a.scope or ""
        # Shorten scope for readability
        if "/resourceGroups/" in scope:
            scope_short = "RG:" + scope.split("/resourceGroups/")[-1].split("/")[0]
        elif scope.startswith("/subscriptions/") and scope.count("/") == 2:
            scope_short = "Subscription"
        elif scope in ("/", ""):
            scope_short = "Root (Tenant)"
        else:
            scope_short = scope

        principals.append({
            "principal_id":   pid,
            "display_name":   resolved.get("display_name", pid),
            "upn":            resolved.get("upn", ""),
            "principal_type": resolved.get("principal_type") or (a.principal_type or "Unknown"),
            "scope":          scope,
            "scope_short":    scope_short,
            "assignment_id":  a.name or ""
        })
    return principals


# ─────────────────────────────────────────────────────────────────
# AZURE: ORCHESTRATION
# ─────────────────────────────────────────────────────────────────

def enumerate_azure(args):
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.authorization import AuthorizationManagementClient
        from azure.mgmt.resource import SubscriptionClient
    except ImportError:
        print("[ERROR] Azure SDK not installed. Run:")
        print("  pip install azure-identity azure-mgmt-authorization azure-mgmt-resource")
        sys.exit(1)

    print("\n[*] Authenticating to Azure (DefaultAzureCredential)...")
    print("    Tries: env vars → workload identity → managed identity → Azure CLI")
    try:
        credential = DefaultAzureCredential()
    except Exception as e:
        print(f"[ERROR] Authentication failed: {e}")
        sys.exit(1)

    # Resolve subscription
    if args.subscription:
        subscription_id = args.subscription
        print(f"    Using subscription: {subscription_id}")
    else:
        print("[*] Discovering subscriptions...")
        sub_client = SubscriptionClient(credential)
        subs = list(sub_client.subscriptions.list())
        if not subs:
            print("[ERROR] No subscriptions found.")
            sys.exit(1)
        if len(subs) == 1:
            subscription_id = subs[0].subscription_id
            print(f"    Using: {subs[0].display_name} ({subscription_id})")
        else:
            for i, s in enumerate(subs):
                print(f"    [{i}] {s.display_name} ({s.subscription_id})")
            subscription_id = subs[int(input("    Select index: "))].subscription_id

    auth_client = AuthorizationManagementClient(credential, subscription_id)

    print(f"\n[*] Fetching all role assignments in subscription {subscription_id}...")
    all_assignments = list(auth_client.role_assignments.list_for_subscription())
    print(f"    Found {len(all_assignments)} role assignments")

    # Batch-resolve all principal display names up front
    unique_pids = list({a.principal_id for a in all_assignments if a.principal_id})
    principal_id_map = {}
    print(f"[*] Resolving {len(unique_pids)} unique principal IDs...")
    _resolve_azure_principals(credential, unique_pids, principal_id_map)

    # Group assignments by role definition
    role_def_to_assignments = defaultdict(list)
    for a in all_assignments:
        role_def_to_assignments[a.role_definition_id].append(a)

    role_counter = Counter({rid: len(asns) for rid, asns in role_def_to_assignments.items()})
    top_roles = role_counter.most_common(args.top)

    print(f"\n[*] Fetching role definitions for top {args.top} roles...")
    role_details = []
    for role_def_id, count in top_roles:
        try:
            role_def = auth_client.role_definitions.get_by_id(role_def_id)
            permissions = []
            dangerous   = []
            for perm in role_def.permissions:
                actions = list(perm.actions or [])
                permissions.append({
                    "Actions":        actions[:15],
                    "NotActions":     list(perm.not_actions or [])[:5],
                    "DataActions":    list(perm.data_actions or [])[:10],
                    "NotDataActions": list(perm.not_data_actions or [])[:5]
                })
                dangerous.extend([
                    a for a in actions if
                    "*" in a or any(k in a.lower() for k in [
                        "microsoft.authorization/",
                        "microsoft.keyvault/",
                        "microsoft.compute/virtualmachines/",
                        "microsoft.storage/storageaccounts/listkeys",
                        "microsoft.resources/subscriptions"
                    ])
                ])

            role_details.append({
                "name":                role_def.role_name,
                "id":                  role_def_id,
                "type":                role_def.role_type,
                "description":         role_def.description,
                "usage_count":         count,
                "permissions":         permissions,
                "dangerous_permissions": dangerous[:10],
                "assigned_principals": _build_azure_principal_list(
                    role_def_to_assignments[role_def_id], principal_id_map
                )
            })
        except Exception as e:
            role_details.append({
                "id":           role_def_id,
                "usage_count":  count,
                "error":        str(e),
                "assigned_principals": _build_azure_principal_list(
                    role_def_to_assignments[role_def_id], principal_id_map
                )
            })

    # Recommendation
    recs = []
    if role_details:
        top = role_details[0]
        principals = top.get("assigned_principals", [])
        sample = ", ".join(
            p.get("display_name") or p.get("principal_id", "?")
            for p in principals[:3]
        )
        recs.append(
            f"Request an Entra ID account with the '{top.get('name', 'unknown')}' role "
            f"({top['usage_count']} assignment(s)"
            + (f"; e.g. {sample}" if sample else "") + ")."
        )
        recs.append(
            "Also request a Kali Linux VM in the same subscription/resource group for interactive testing."
        )

    return {
        "provider":        "Azure",
        "subscription_id": subscription_id,
        "enumerated_at":   datetime.utcnow().isoformat() + "Z",
        "top_roles":       role_details,
        "recommendation":  recs
    }


# ─────────────────────────────────────────────────────────────────
# OUTPUT: TEXT PRINTING
# ─────────────────────────────────────────────────────────────────

W = 74  # Console width

def _dangerous_perms(permissions_summary):
    out = []
    for stmt in permissions_summary:
        if isinstance(stmt, dict) and "error" not in stmt:
            out.extend(stmt.get("DangerousPermissions", []))
    return list(set(out))


def print_aws_results(results):
    print("\n" + "=" * W)
    print("  AWS ROLE ENUMERATION RESULTS")
    print(f"  Account : {results['account']}")
    print(f"  Caller  : {results['caller_arn']}")
    print(f"  Time    : {results['enumerated_at']}")
    print("=" * W)

    # User / Group Policies
    print(f"\n{'─' * W}")
    print("  TOP USER / GROUP POLICIES")
    print(f"{'─' * W}")
    for i, role in enumerate(results["top_user_group_roles"], 1):
        name = role.get("name", role.get("arn", "Unknown"))
        print(f"\n  #{i}  {name}")
        print(f"       ARN    : {role.get('arn', 'N/A')}")
        print(f"       Type   : {role.get('type', 'N/A')}")
        print(f"       Count  : {role['usage_count']} effective user assignment(s)")

        dangerous = _dangerous_perms(role.get("permissions_summary", []))
        if dangerous:
            print(f"       ⚠ HIGH-VALUE PERMS : {', '.join(dangerous[:6])}")

        users = role.get("assigned_users", [])
        if users:
            print(f"       Assigned Users ({len(users)}):")
            for u in users:
                print(f"         • {u['username']:<32}  {u['user_arn']}")
                print(f"           source: {u['source']}")
        else:
            print("       Assigned Users : (none resolved)")

    # Instance Profile Roles
    print(f"\n{'─' * W}")
    print("  TOP INSTANCE PROFILE ROLES")
    print(f"{'─' * W}")
    for i, role in enumerate(results["top_instance_profile_roles"], 1):
        name = role.get("name", role.get("arn", "Unknown"))
        print(f"\n  #{i}  {name}")
        print(f"       ARN               : {role.get('arn', 'N/A')}")
        print(f"       Type              : {role.get('type', 'N/A')}")
        print(f"       Instance Profiles : {', '.join(role.get('instance_profiles', []))}")

        dangerous = _dangerous_perms(role.get("permissions_summary", []))
        if dangerous:
            print(f"       ⚠ HIGH-VALUE PERMS   : {', '.join(dangerous[:6])}")

        instances = role.get("assigned_instances", [])
        if instances:
            print(f"       EC2 Instances ({len(instances)}):")
            for inst in instances:
                print(f"         • {inst['instance_id']:<22}  Name: {inst['name']:<28}  [{inst['state']}]")
        else:
            print("       EC2 Instances : (none resolved — profile may be unattached or describe_instances denied)")

    print(f"\n{'─' * W}")
    print("  RECOMMENDATIONS")
    print(f"{'─' * W}")
    for rec in results["recommendation"]:
        print(f"\n  → {rec}")
    print()


def print_azure_results(results):
    print("\n" + "=" * W)
    print("  AZURE ROLE ENUMERATION RESULTS")
    print(f"  Subscription : {results['subscription_id']}")
    print(f"  Time         : {results['enumerated_at']}")
    print("=" * W)

    print(f"\n{'─' * W}")
    print("  TOP ASSIGNED ROLES")
    print(f"{'─' * W}")
    for i, role in enumerate(results["top_roles"], 1):
        has_def = "name" in role
        print(f"\n  #{i}  {role.get('name', '[definition unavailable]')}")
        if not has_def and "error" in role:
            print(f"       Error : {role['error']}")
        else:
            print(f"       Type        : {role.get('type', 'N/A')}")
            print(f"       Assignments : {role['usage_count']}")
            desc = (role.get("description") or "N/A")[:90]
            print(f"       Description : {desc}")

            dangerous = role.get("dangerous_permissions", [])
            if dangerous:
                print(f"       ⚠ HIGH-VALUE PERMS : {', '.join(dangerous[:6])}")

        principals = role.get("assigned_principals", [])
        if principals:
            print(f"       Assigned Principals ({len(principals)}):")
            for p in principals:
                ptype = f"[{p.get('principal_type', '?')}]"
                name  = p.get("display_name") or p.get("principal_id", "?")
                upn   = f"  <{p['upn']}>" if p.get("upn") else ""
                scope = p.get("scope_short", p.get("scope", ""))
                print(f"         • {name:<38}{upn}")
                print(f"           {ptype}  scope={scope}")
        else:
            print("       Assigned Principals : (none resolved)")

    print(f"\n{'─' * W}")
    print("  RECOMMENDATIONS")
    print(f"{'─' * W}")
    for rec in results["recommendation"]:
        print(f"\n  → {rec}")
    print()


# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    print("=" * W)
    print("  CPT Day-1 Role Enumeration Script")
    print(f"  Provider : {args.provider.upper()}")
    print(f"  Top N    : {args.top}")
    print("=" * W)

    results = enumerate_aws(args) if args.provider == "aws" else enumerate_azure(args)

    if args.output == "json":
        output_str = json.dumps(results, indent=2, default=str)
        print(output_str)
    else:
        print_aws_results(results) if args.provider == "aws" else print_azure_results(results)
        output_str = json.dumps(results, indent=2, default=str)

    save_path = args.save
    if not save_path:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        save_path = f"cpt_role_enum_{args.provider}_{ts}.json"

    with open(save_path, "w") as f:
        f.write(output_str)
    print(f"[*] Full JSON saved to: {save_path}")


if __name__ == "__main__":
    main()
