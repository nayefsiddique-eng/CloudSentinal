import json
import os
import random

os.makedirs("dataset/secure", exist_ok=True)
os.makedirs("dataset/vulnerable", exist_ok=True)
os.makedirs("dataset/labels", exist_ok=True)

def s3_config(public, versioning, encryption, idx):
    return {
        "resource_type": "s3_bucket",
        "resource_id": f"bucket-{idx:04d}",
        "config": {
            "public_access_block": {
                "BlockPublicAcls": not public,
                "IgnorePublicAcls": not public,
                "BlockPublicPolicy": not public,
                "RestrictPublicBuckets": not public,
            },
            "versioning": "Enabled" if versioning else "Disabled",
            "encryption_enabled": encryption,
        },
        "label": "MISCONFIGURED" if public or not versioning or not encryption else "SECURE",
        "category": "PUBLIC_ACCESS" if public else ("DATA_PROTECTION" if (not versioning or not encryption) else "NONE"),
        "severity": "HIGH" if public else ("MEDIUM" if (not versioning or not encryption) else "INFO"),
    }

def iam_config(mfa, wildcard, old_key, idx):
    return {
        "resource_type": "iam_user",
        "resource_id": f"user-{idx:04d}",
        "config": {
            "mfa_enabled": mfa,
            "wildcard_permissions": wildcard,
            "old_access_key_days": 120 if old_key else 10,
        },
        "label": "MISCONFIGURED" if (not mfa or wildcard or old_key) else "SECURE",
        "category": "IDENTITY_SECURITY" if not mfa else ("EXCESSIVE_PERMISSIONS" if wildcard else "CREDENTIAL_HYGIENE"),
        "severity": "HIGH" if not mfa else ("CRITICAL" if wildcard else ("MEDIUM" if old_key else "INFO")),
    }

def sg_config(ssh_open, rdp_open, unrestricted, idx):
    return {
        "resource_type": "security_group",
        "resource_id": f"sg-{idx:04d}",
        "config": {
            "ssh_open_to_world": ssh_open,
            "rdp_open_to_world": rdp_open,
            "unrestricted_inbound": unrestricted,
        },
        "label": "MISCONFIGURED" if (ssh_open or rdp_open or unrestricted) else "SECURE",
        "category": "NETWORK_SECURITY",
        "severity": "CRITICAL" if (ssh_open or rdp_open or unrestricted) else "INFO",
    }

def cloudtrail_config(logging_enabled, idx):
    return {
        "resource_type": "cloudtrail",
        "resource_id": f"trail-{idx:04d}",
        "config": {
            "logging_enabled": logging_enabled,
        },
        "label": "MISCONFIGURED" if not logging_enabled else "SECURE",
        "category": "LOGGING_MONITORING",
        "severity": "HIGH" if not logging_enabled else "INFO",
    }

def lambda_config(excessive_perms, public_url, has_secret_env, kms_encrypted, idx):
    is_bad = excessive_perms or public_url or has_secret_env
    return {
        "resource_type": "lambda_function",
        "resource_id": f"function-{idx:04d}",
        "config": {
            "excessive_permissions": excessive_perms,
            "public_function_url": public_url,
            "secrets_in_env": has_secret_env,
            "kms_encrypted": kms_encrypted,
        },
        "label": "MISCONFIGURED" if is_bad else "SECURE",
        "category": "EXCESSIVE_PERMISSIONS" if excessive_perms else ("PUBLIC_ACCESS" if public_url else ("CREDENTIAL_HYGIENE" if has_secret_env else "DATA_PROTECTION")),
        "severity": "CRITICAL" if excessive_perms else ("HIGH" if (public_url or has_secret_env) else ("LOW" if not kms_encrypted else "INFO")),
    }

all_labels = []
idx = 1

for _ in range(80):
    public = random.random() < 0.35
    versioning = random.random() > 0.4
    encryption = random.random() > 0.2
    cfg = s3_config(public, versioning, encryption, idx)
    folder = "vulnerable" if cfg["label"] == "MISCONFIGURED" else "secure"
    fname = f"dataset/{folder}/s3_{idx:04d}.json"
    with open(fname, "w") as f:
        json.dump(cfg, f, indent=2)
    all_labels.append({"file": fname, **{k: cfg[k] for k in ("resource_type", "label", "category", "severity")}})
    idx += 1

for _ in range(80):
    mfa = random.random() > 0.35
    wildcard = random.random() < 0.15
    old_key = random.random() < 0.3
    cfg = iam_config(mfa, wildcard, old_key, idx)
    folder = "vulnerable" if cfg["label"] == "MISCONFIGURED" else "secure"
    fname = f"dataset/{folder}/iam_{idx:04d}.json"
    with open(fname, "w") as f:
        json.dump(cfg, f, indent=2)
    all_labels.append({"file": fname, **{k: cfg[k] for k in ("resource_type", "label", "category", "severity")}})
    idx += 1

for _ in range(80):
    ssh_open = random.random() < 0.3
    rdp_open = random.random() < 0.2
    unrestricted = random.random() < 0.1
    cfg = sg_config(ssh_open, rdp_open, unrestricted, idx)
    folder = "vulnerable" if cfg["label"] == "MISCONFIGURED" else "secure"
    fname = f"dataset/{folder}/sg_{idx:04d}.json"
    with open(fname, "w") as f:
        json.dump(cfg, f, indent=2)
    all_labels.append({"file": fname, **{k: cfg[k] for k in ("resource_type", "label", "category", "severity")}})
    idx += 1

for _ in range(40):
    logging_enabled = random.random() > 0.3
    cfg = cloudtrail_config(logging_enabled, idx)
    folder = "vulnerable" if cfg["label"] == "MISCONFIGURED" else "secure"
    fname = f"dataset/{folder}/cloudtrail_{idx:04d}.json"
    with open(fname, "w") as f:
        json.dump(cfg, f, indent=2)
    all_labels.append({"file": fname, **{k: cfg[k] for k in ("resource_type", "label", "category", "severity")}})
    idx += 1

for _ in range(60):
    excessive_perms = random.random() < 0.2
    public_url = random.random() < 0.25
    has_secret_env = random.random() < 0.2
    kms_encrypted = random.random() > 0.5
    cfg = lambda_config(excessive_perms, public_url, has_secret_env, kms_encrypted, idx)
    folder = "vulnerable" if cfg["label"] == "MISCONFIGURED" else "secure"
    fname = f"dataset/{folder}/lambda_{idx:04d}.json"
    with open(fname, "w") as f:
        json.dump(cfg, f, indent=2)
    all_labels.append({"file": fname, **{k: cfg[k] for k in ("resource_type", "label", "category", "severity")}})
    idx += 1

with open("dataset/labels/ground_truth.json", "w") as f:
    json.dump(all_labels, f, indent=2)

print(f"Generated {idx - 1} labeled configs.")
print(f"Secure: {sum(1 for l in all_labels if l['label'] == 'SECURE')}")
print(f"Vulnerable: {sum(1 for l in all_labels if l['label'] == 'MISCONFIGURED')}")
