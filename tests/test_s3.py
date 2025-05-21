import pytest
from unittest.mock import Mock, patch
from scanner.s3 import scan


@pytest.fixture
def mock_s3_client():
    with patch('boto3.client') as mock_client:
        s3 = Mock()
        mock_client.return_value = s3
        yield s3


def test_scan_s3_public_access(mock_s3_client):
    # Setup mock response
    mock_s3_client.list_buckets.return_value = {
        'Buckets': [{'Name': 'test-bucket'}]
    }
    mock_s3_client.get_bucket_acl.return_value = {
        'Grants': [{
            'Grantee': {
                'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'
            },
            'Permission': 'READ'
        }]
    }

    # Run scan
    findings = scan()

    # Assert
    assert len(findings) > 0
    assert any(
        f['issue'] == 'Bucket is publicly accessible'
        for f in findings
    )


def test_scan_s3_versioning_disabled(mock_s3_client):
    # Setup mock response
    mock_s3_client.list_buckets.return_value = {
        'Buckets': [{'Name': 'test-bucket'}]
    }
    mock_s3_client.get_bucket_acl.return_value = {
        'Grants': []
    }
    mock_s3_client.get_bucket_versioning.return_value = {
        'Status': 'Disabled'
    }

    # Run scan
    findings = scan()

    # Assert
    assert len(findings) > 0
    assert any(
        f['issue'] == 'Bucket versioning is not enabled'
        for f in findings
    )


def test_scan_s3_logging_disabled(mock_s3_client):
    # Setup mock response
    mock_s3_client.list_buckets.return_value = {
        'Buckets': [{'Name': 'test-bucket'}]
    }
    mock_s3_client.get_bucket_acl.return_value = {
        'Grants': []
    }
    mock_s3_client.get_bucket_versioning.return_value = {
        'Status': 'Enabled'
    }
    mock_s3_client.get_bucket_logging.return_value = {}

    # Run scan
    findings = scan()

    # Assert
    assert len(findings) > 0
    assert any(
        f['issue'] == 'Bucket access logging is not enabled'
        for f in findings
    )


def test_scan_s3_encryption_disabled(mock_s3_client):
    # Setup mock response
    mock_s3_client.list_buckets.return_value = {
        'Buckets': [{'Name': 'test-bucket'}]
    }
    mock_s3_client.get_bucket_acl.return_value = {
        'Grants': []
    }
    mock_s3_client.get_bucket_versioning.return_value = {
        'Status': 'Enabled'
    }
    mock_s3_client.get_bucket_logging.return_value = {
        'LoggingEnabled': True
    }
    mock_s3_client.get_bucket_encryption.side_effect = Exception(
        'ServerSideEncryptionConfigurationNotFoundError'
    )

    # Run scan
    findings = scan()

    # Assert
    assert len(findings) > 0
    assert any(
        f['issue'] == 'Bucket encryption is not enabled'
        for f in findings
    )
