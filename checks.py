import boto3
from botocore.exceptions import ClientError

def check_s3_public_access():
    """
    Scans all S3 buckets in the account and checks for public access permissions.
    Returns a list of findings.
    """
    print("[*] Checking for publicly accessible S3 buckets...")
    s3_client = boto3.client('s3')
    findings = []

    try:
        response = s3_client.list_buckets()
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            is_public = False
            
            try:
                pub_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                config = pub_access_block['PublicAccessBlockConfiguration']
                if not (config['BlockPublicAcls'] and config['BlockPublicPolicy'] and 
                        config['IgnorePublicAcls'] and config['RestrictPublicBuckets']):
                    is_public = True
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    try:
                        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                        for grant in acl['Grants']:
                            grantee = grant.get('Grantee', {})
                            uri = grantee.get('URI', '')
                            if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                                is_public = True
                                break
                    except ClientError:
                        pass
            
            if is_public:
                finding = {
                    "resource": bucket_name,
                    "finding": "S3 Bucket is potentially public.",
                    "recommendation": "Enable all 'Block public access' settings for this bucket."
                }
                findings.append(finding)

    except ClientError as e:
        print(f"  [!] Error connecting to AWS S3: {e}. Check your credentials and permissions.")
        return []
        
    print(f"  [+] S3 check complete. Found {len(findings)} potential issues.")
    return findings


# --- NEW FUNCTION ---
def check_open_security_groups():
    """
    Scans all EC2 security groups for rules that allow unrestricted access to sensitive ports.
    Returns a list of findings.
    """
    print("[*] Checking for open security groups on sensitive ports...")
    ec2_client = boto3.client('ec2')
    findings = []
    sensitive_ports = [22, 3389] # SSH and RDP

    try:
        response = ec2_client.describe_security_groups()
        for group in response['SecurityGroups']:
            group_id = group['GroupId']
            for permission in group['IpPermissions']:
                for ip_range in permission.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        # Check if 'FromPort' and 'ToPort' are defined
                        from_port = permission.get('FromPort')
                        to_port = permission.get('ToPort')
                        if from_port is not None and to_port is not None:
                             for port in range(from_port, to_port + 1):
                                if port in sensitive_ports:
                                    finding = {
                                        "resource": f"{group_id} (Port {port})",
                                        "finding": "Security group has a sensitive port open to the entire internet.",
                                        "recommendation": "Restrict the inbound rule to a specific, trusted IP address range instead of '0.0.0.0/0'."
                                    }
                                    findings.append(finding)
                                    break # Move to the next permission
    
    except ClientError as e:
        print(f"  [!] Error connecting to AWS EC2: {e}. Check your credentials and permissions.")
        return []

    print(f"  [+] Security group check complete. Found {len(findings)} potential issues.")
    return findings


