import pytest
from unittest.mock import Mock, patch
from scanner.ec2 import scan


@pytest.fixture
def mock_ec2_client():
    with patch('boto3.client') as mock_client:
        ec2 = Mock()
        mock_client.return_value = ec2
        yield ec2


def test_scan_ec2_public_ip(mock_ec2_client):
    # Setup mock response
    mock_ec2_client.describe_instances.return_value = {
        'Reservations': [{
            'Instances': [{
                'InstanceId': 'i-1234567890',
                'NetworkInterfaces': [{
                    'Association': {'PublicIp': '1.2.3.4'}
                }]
            }]
        }]
    }
    mock_ec2_client.describe_snapshots.return_value = {
        'Snapshots': []
    }

    # Run scan
    findings = scan()

    # Assert
    assert len(findings) > 0
    assert any(f['issue'] == 'Instance has public IP' for f in findings)


def test_scan_ec2_termination_protection(mock_ec2_client):
    # Setup mock response
    mock_ec2_client.describe_instances.return_value = {
        'Reservations': [{
            'Instances': [{
                'InstanceId': 'i-1234567890',
                'NetworkInterfaces': []
            }]
        }]
    }
    mock_ec2_client.describe_instance_attribute.return_value = {
        'DisableApiTermination': {'Value': False}
    }
    mock_ec2_client.describe_snapshots.return_value = {
        'Snapshots': []
    }

    # Run scan
    findings = scan()

    # Assert
    assert len(findings) > 0
    assert any(
        f['issue'] == 'Instance termination protection is not enabled'
        for f in findings
    )


def test_scan_ec2_unencrypted_volumes(mock_ec2_client):
    # Setup mock response
    mock_ec2_client.describe_instances.return_value = {
        'Reservations': [{
            'Instances': [{
                'InstanceId': 'i-1234567890',
                'NetworkInterfaces': [],
                'BlockDeviceMappings': [{
                    'Ebs': {'VolumeId': 'vol-1234567890'}
                }]
            }]
        }]
    }
    mock_ec2_client.describe_volumes.return_value = {
        'Volumes': [{
            'VolumeId': 'vol-1234567890',
            'Encrypted': False
        }]
    }
    mock_ec2_client.describe_snapshots.return_value = {
        'Snapshots': []
    }

    # Run scan
    findings = scan()

    # Assert
    assert len(findings) > 0
    assert any(f['issue'] == 'Volume is not encrypted' for f in findings)


def test_scan_ec2_public_snapshot(mock_ec2_client):
    # Setup mock response
    mock_ec2_client.describe_instances.return_value = {
        'Reservations': [{
            'Instances': [{
                'InstanceId': 'i-1234567890',
                'NetworkInterfaces': []
            }]
        }]
    }
    mock_ec2_client.describe_snapshots.return_value = {
        'Snapshots': [{
            'SnapshotId': 'snap-1234567890'
        }]
    }
    mock_ec2_client.describe_snapshot_attribute.return_value = {
        'CreateVolumePermissions': [{
            'Group': 'all'
        }]
    }

    # Run scan
    findings = scan()

    # Assert
    assert len(findings) > 0
    assert any(
        f['issue'] == 'Snapshot is publicly accessible'
        for f in findings
    )
