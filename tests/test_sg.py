import pytest
from unittest.mock import Mock, patch
from scanner.sg import scan

@pytest.fixture
def mock_ec2_client():
    with patch('boto3.client') as mock_client:
        ec2 = Mock()
        mock_client.return_value = ec2
        yield ec2

def test_scan_sg_ssh_open(mock_ec2_client):
    # Setup mock response
    mock_ec2_client.describe_security_groups.return_value = {
        'SecurityGroups': [{
            'GroupId': 'sg-1234567890',
            'IpPermissions': [{
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        }]
    }

    # Run scan
    findings = scan()

    # Assert
    assert len(findings) > 0
    assert any(f['issue'] == 'Open to the world on port 22' for f in findings)

def test_scan_sg_http_open(mock_ec2_client):
    # Setup mock response
    mock_ec2_client.describe_security_groups.return_value = {
        'SecurityGroups': [{
            'GroupId': 'sg-1234567890',
            'IpPermissions': [{
                'FromPort': 80,
                'ToPort': 80,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        }]
    }

    # Run scan
    findings = scan()

    # Assert
    assert len(findings) > 0
    assert any(f['issue'] == 'Open to the world on port 80' for f in findings)

def test_scan_sg_https_open(mock_ec2_client):
    # Setup mock response
    mock_ec2_client.describe_security_groups.return_value = {
        'SecurityGroups': [{
            'GroupId': 'sg-1234567890',
            'IpPermissions': [{
                'FromPort': 443,
                'ToPort': 443,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        }]
    }

    # Run scan
    findings = scan()

    # Assert
    assert len(findings) > 0
    assert any(f['issue'] == 'Open to the world on port 443' for f in findings)

def test_scan_sg_rdp_open(mock_ec2_client):
    # Setup mock response
    mock_ec2_client.describe_security_groups.return_value = {
        'SecurityGroups': [{
            'GroupId': 'sg-1234567890',
            'IpPermissions': [{
                'FromPort': 3389,
                'ToPort': 3389,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        }]
    }

    # Run scan
    findings = scan()

    # Assert
    assert len(findings) > 0
    assert any(f['issue'] == 'Open to the world on port 3389' for f in findings) 