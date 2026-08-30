import pytest
from unittest.mock import MagicMock, patch
from backend.services.aws import s3, iam, ec2, cloudtrail, lambda_scanner


# --- S3 tests ---

def test_is_bucket_public_true():
    with patch("backend.services.aws.s3.get_client") as mock_client:
        s3_mock = MagicMock()
        s3_mock.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False, "IgnorePublicAcls": False,
                "BlockPublicPolicy": False, "RestrictPublicBuckets": False
            }
        }
        s3_mock.get_bucket_acl.return_value = {
            "Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]
        }
        mock_client.return_value = s3_mock
        assert s3.is_bucket_public("test-bucket") is True


def test_is_bucket_public_false():
    with patch("backend.services.aws.s3.get_client") as mock_client:
        s3_mock = MagicMock()
        s3_mock.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True
            }
        }
        mock_client.return_value = s3_mock
        assert s3.is_bucket_public("test-bucket") is False


def test_is_versioning_enabled_true():
    with patch("backend.services.aws.s3.get_client") as mock_client:
        s3_mock = MagicMock()
        s3_mock.get_bucket_versioning.return_value = {"Status": "Enabled"}
        mock_client.return_value = s3_mock
        assert s3.is_versioning_enabled("test-bucket") is True


def test_is_versioning_enabled_false():
    with patch("backend.services.aws.s3.get_client") as mock_client:
        s3_mock = MagicMock()
        s3_mock.get_bucket_versioning.return_value = {}
        mock_client.return_value = s3_mock
        assert s3.is_versioning_enabled("test-bucket") is False


# --- IAM tests ---

def test_has_mfa_enabled_true():
    with patch("backend.services.aws.iam.get_client") as mock_client:
        iam_mock = MagicMock()
        iam_mock.list_mfa_devices.return_value = {"MFADevices": [{"SerialNumber": "arn:aws:iam::123:mfa/test"}]}
        mock_client.return_value = iam_mock
        assert iam.has_mfa_enabled("testuser") is True


def test_has_mfa_enabled_false():
    with patch("backend.services.aws.iam.get_client") as mock_client:
        iam_mock = MagicMock()
        iam_mock.list_mfa_devices.return_value = {"MFADevices": []}
        mock_client.return_value = iam_mock
        assert iam.has_mfa_enabled("testuser") is False


def test_policy_has_wildcard_true():
    doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    assert iam._policy_has_wildcard(doc) is True


def test_policy_has_wildcard_false():
    doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::mybucket/*"}]}
    assert iam._policy_has_wildcard(doc) is False


def test_root_account_has_mfa_true():
    with patch("backend.services.aws.iam.get_client") as mock_client:
        iam_mock = MagicMock()
        iam_mock.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}
        mock_client.return_value = iam_mock
        assert iam.root_account_has_mfa() is True


def test_root_account_has_mfa_false():
    with patch("backend.services.aws.iam.get_client") as mock_client:
        iam_mock = MagicMock()
        iam_mock.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
        mock_client.return_value = iam_mock
        assert iam.root_account_has_mfa() is False


def test_weak_password_policy_no_policy_set():
    with patch("backend.services.aws.iam.get_client") as mock_client:
        iam_mock = MagicMock()
        iam_mock.exceptions.NoSuchEntityException = Exception
        iam_mock.get_account_password_policy.side_effect = iam_mock.exceptions.NoSuchEntityException
        mock_client.return_value = iam_mock
        result = iam.has_weak_password_policy()
        assert result["weak"] is True


def test_weak_password_policy_meets_baseline():
    with patch("backend.services.aws.iam.get_client") as mock_client:
        iam_mock = MagicMock()
        iam_mock.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 14,
                "RequireSymbols": True,
                "RequireNumbers": True,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
            }
        }
        mock_client.return_value = iam_mock
        result = iam.has_weak_password_policy()
        assert result["weak"] is False


# --- EC2 tests ---

def test_find_open_risky_ports_ssh_open():
    sg = {
        "IpPermissions": [
            {"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ]
    }
    result = ec2.find_open_risky_ports(sg)
    assert {"port": 22, "service": "SSH"} in result


def test_find_open_risky_ports_none_open():
    sg = {
        "IpPermissions": [
            {"FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ]
    }
    result = ec2.find_open_risky_ports(sg)
    assert result == []


def test_has_unrestricted_inbound_true():
    sg = {
        "IpPermissions": [
            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ]
    }
    assert ec2.has_unrestricted_inbound(sg) is True


def test_has_unrestricted_inbound_false():
    sg = {
        "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ]
    }
    assert ec2.has_unrestricted_inbound(sg) is False


# --- CloudTrail tests ---

def test_is_trail_logging_true():
    with patch("backend.services.aws.cloudtrail.get_client") as mock_client:
        ct_mock = MagicMock()
        ct_mock.get_trail_status.return_value = {"IsLogging": True}
        mock_client.return_value = ct_mock
        assert cloudtrail.is_trail_logging("test-trail") is True


def test_is_trail_logging_false():
    with patch("backend.services.aws.cloudtrail.get_client") as mock_client:
        ct_mock = MagicMock()
        ct_mock.get_trail_status.return_value = {"IsLogging": False}
        mock_client.return_value = ct_mock
        assert cloudtrail.is_trail_logging("test-trail") is False


def test_scan_cloudtrail_no_trails():
    with patch("backend.services.aws.cloudtrail.list_trails", return_value=[]):
        findings = cloudtrail.scan_cloudtrail()
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["status"] == "OPEN"


# --- Lambda tests ---

def test_has_public_function_url_true():
    with patch("backend.services.aws.lambda_scanner.get_client") as mock_client:
        lam_mock = MagicMock()
        lam_mock.get_function_url_config.return_value = {"AuthType": "NONE"}
        mock_client.return_value = lam_mock
        assert lambda_scanner.has_public_function_url("test-fn") is True


def test_has_public_function_url_false_when_not_found():
    with patch("backend.services.aws.lambda_scanner.get_client") as mock_client:
        lam_mock = MagicMock()
        lam_mock.exceptions.ResourceNotFoundException = Exception
        lam_mock.get_function_url_config.side_effect = lam_mock.exceptions.ResourceNotFoundException
        mock_client.return_value = lam_mock
        assert lambda_scanner.has_public_function_url("test-fn") is False


def test_has_secrets_in_env_detects_flagged_keys():
    with patch("backend.services.aws.lambda_scanner.get_client") as mock_client:
        lam_mock = MagicMock()
        lam_mock.get_function_configuration.return_value = {
            "Environment": {"Variables": {"DB_PASSWORD": "x", "SAFE_VAR": "y"}}
        }
        mock_client.return_value = lam_mock
        result = lambda_scanner.has_secrets_in_env("test-fn")
        assert "DB_PASSWORD" in result
        assert "SAFE_VAR" not in result


def test_has_secrets_in_env_clean():
    with patch("backend.services.aws.lambda_scanner.get_client") as mock_client:
        lam_mock = MagicMock()
        lam_mock.get_function_configuration.return_value = {
            "Environment": {"Variables": {"REGION": "us-east-1"}}
        }
        mock_client.return_value = lam_mock
        result = lambda_scanner.has_secrets_in_env("test-fn")
        assert result == []


def test_has_encryption_configured_true():
    assert lambda_scanner.has_encryption_configured({"KMSKeyArn": "arn:aws:kms:us-east-1:123:key/abc"}) is True


def test_has_encryption_configured_false():
    assert lambda_scanner.has_encryption_configured({}) is False
