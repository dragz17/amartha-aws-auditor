import pytest
from unittest.mock import Mock, patch
from scanner.iam import scan


@pytest.fixture
def mock_iam_client():
    with patch('boto3.client') as mock_client:
        iam = Mock()
        mock_client.return_value = iam
        yield iam


def test_scan_iam_user_without_mfa(mock_iam_client):
    # Setup mock response
    mock_iam_client.list_users.return_value = {
        'Users': [{'UserName': 'testuser'}]
    }
    mock_iam_client.list_mfa_devices.return_value = {
        'MFADevices': []
    }
    mock_iam_client.list_user_policies.return_value = {
        'PolicyNames': []
    }
    mock_iam_client.list_attached_user_policies.return_value = {
        'AttachedPolicies': []
    }

    # Run scan
    findings = scan()

    # Assert
    assert len(findings) > 0
    assert any(
        f['issue'] == 'User does not have MFA enabled'
        for f in findings
    )


def test_scan_iam_overly_permissive_policy(mock_iam_client):
    # Setup mock response
    mock_iam_client.list_users.return_value = {
        'Users': [{'UserName': 'testuser'}]
    }
    mock_iam_client.list_mfa_devices.return_value = {
        'MFADevices': [{'SerialNumber': 'test-mfa'}]
    }
    mock_iam_client.list_user_policies.return_value = {
        'PolicyNames': ['test-policy']
    }
    mock_iam_client.get_user_policy.return_value = {
        'PolicyDocument': {
            'Statement': [{
                'Effect': 'Allow',
                'Action': '*',
                'Resource': '*'
            }]
        }
    }
    mock_iam_client.list_attached_user_policies.return_value = {
        'AttachedPolicies': []
    }

    # Run scan
    findings = scan()

    # Assert
    assert len(findings) > 0
    assert any(
        f['issue'] == 'Inline policy is overly permissive'
        for f in findings
    )


def test_scan_iam_password_policy(mock_iam_client):
    # Setup mock response
    mock_iam_client.list_users.return_value = {
        'Users': [{'UserName': 'testuser'}]
    }
    mock_iam_client.list_mfa_devices.return_value = {
        'MFADevices': [{'SerialNumber': 'test-mfa'}]
    }
    mock_iam_client.list_user_policies.return_value = {
        'PolicyNames': []
    }
    mock_iam_client.list_attached_user_policies.return_value = {
        'AttachedPolicies': []
    }
    mock_iam_client.get_account_password_policy.return_value = {
        'PasswordPolicy': {
            'RequireUppercaseCharacters': False
        }
    }

    # Run scan
    findings = scan()

    # Assert
    assert len(findings) > 0
    assert any(
        f['issue'] == 'Password policy does not require uppercase letters'
        for f in findings
    )
