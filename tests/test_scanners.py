import pytest
from unittest.mock import MagicMock, patch
from backend.services.aws import s3, iam, ec2


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
