import boto3
from .rules import cis_rules


def scan():
    findings = []
    ec2 = boto3.client('ec2')
    instances = ec2.describe_instances()

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']

            # Check public IP
            for iface in instance.get('NetworkInterfaces', []):
                if iface.get('Association', {}).get('PublicIp'):
                    findings.append({
                        "resource": instance_id,
                        "type": "EC2 Instance",
                        "risk": (
                            cis_rules["ec2_public_ip"]["risk_level"]
                        ),
                        "issue": "Instance has public IP",
                        "cis_rule": (
                            cis_rules["ec2_public_ip"]["cis_rule"]
                        ),
                        "remediation": (
                            cis_rules["ec2_public_ip"]["remediation"]
                        )
                    })

            # Check termination protection
            try:
                attributes = ec2.describe_instance_attribute(
                    InstanceId=instance_id,
                    Attribute='disableApiTermination'
                )
                if not attributes['DisableApiTermination']['Value']:
                    findings.append({
                        "resource": instance_id,
                        "type": "EC2 Instance",
                        "risk": (
                            cis_rules["ec2_termination_protection"]
                            ["risk_level"]
                        ),
                        "issue": "Instance termination protection is not enabled",
                        "cis_rule": (
                            cis_rules["ec2_termination_protection"]
                            ["cis_rule"]
                        ),
                        "remediation": (
                            cis_rules["ec2_termination_protection"]
                            ["remediation"]
                        )
                    })
            except Exception as e:
                print(
                    f"Error checking termination protection for {instance_id}: {e}"
                )

            # Check volume encryption
            for block_device in instance.get('BlockDeviceMappings', []):
                if 'Ebs' in block_device:
                    volume_id = block_device['Ebs']['VolumeId']
                    try:
                        volume = ec2.describe_volumes(
                            VolumeIds=[volume_id]
                        )['Volumes'][0]
                        if not volume.get('Encrypted'):
                            findings.append({
                                "resource": f"{instance_id} - {volume_id}",
                                "type": "EC2 Volume",
                                "risk": (
                                    cis_rules["ec2_unencrypted_volumes"]
                                    ["risk_level"]
                                ),
                                "issue": "Volume is not encrypted",
                                "cis_rule": (
                                    cis_rules["ec2_unencrypted_volumes"]
                                    ["cis_rule"]
                                ),
                                "remediation": (
                                    cis_rules["ec2_unencrypted_volumes"]
                                    ["remediation"]
                                )
                            })
                    except Exception as e:
                        print(
                            f"Error checking volume encryption for {volume_id}: {e}"
                        )

    # Check public snapshots
    snapshots = ec2.describe_snapshots(OwnerIds=['self'])['Snapshots']
    for snapshot in snapshots:
        try:
            attributes = ec2.describe_snapshot_attribute(
                SnapshotId=snapshot['SnapshotId'],
                Attribute='createVolumePermission'
            )
            for permission in attributes.get('CreateVolumePermissions', []):
                if permission.get('Group') == 'all':
                    findings.append({
                        "resource": snapshot['SnapshotId'],
                        "type": "EC2 Snapshot",
                        "risk": (
                            cis_rules["ec2_public_snapshot"]
                            ["risk_level"]
                        ),
                        "issue": "Snapshot is publicly accessible",
                        "cis_rule": (
                            cis_rules["ec2_public_snapshot"]
                            ["cis_rule"]
                        ),
                        "remediation": (
                            cis_rules["ec2_public_snapshot"]
                            ["remediation"]
                        )
                    })
        except Exception as e:
            print(
                f"Error checking snapshot permissions for "
                f"{snapshot['SnapshotId']}: {e}"
            )

    return findings
