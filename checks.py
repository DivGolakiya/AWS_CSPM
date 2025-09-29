import boto3
from botocore.exceptions import ClientError

def check_s3_public_access(quiet=False):
    """Scans S3 buckets for public access."""
    if not quiet:
        print("[*] Checking for publicly accessible S3 buckets...")
    s3_client = boto3.client('s3')
    findings = []
    # ... (rest of the function logic is the same)
    try:
        response = s3_client.list_buckets()
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            is_public = False
            try:
                pub_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                config = pub_access_block['PublicAccessBlockConfiguration']
                if not (config['BlockPublicAcls'] and config['BlockPublicPolicy'] and config['IgnorePublicAcls'] and config['RestrictPublicBuckets']):
                    is_public = True
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    try:
                        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                        for grant in acl['Grants']:
                            if 'AllUsers' in grant.get('Grantee', {}).get('URI', '') or 'AuthenticatedUsers' in grant.get('Grantee', {}).get('URI', ''):
                                is_public = True; break
                    except ClientError: pass
            if is_public:
                findings.append({ "resource": bucket_name, "finding": "S3 Bucket is potentially public.", "recommendation": "Enable all 'Block public access' settings."})
    except ClientError as e:
        if not quiet: print(f"  [!] Error connecting to AWS S3: {e}.")
        return []
    if not quiet:
        print(f"  [+] S3 check complete. Found {len(findings)} potential issues.")
    return findings

def check_open_security_groups(quiet=False):
    """Scans EC2 security groups for open sensitive ports."""
    if not quiet:
        print("[*] Checking for open security groups on sensitive ports...")
    ec2_client = boto3.client('ec2')
    findings = []
    sensitive_ports = [22, 3389]
    # ... (rest of the function logic is the same)
    try:
        response = ec2_client.describe_security_groups()
        for group in response['SecurityGroups']:
            for permission in group['IpPermissions']:
                for ip_range in permission.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        from_port, to_port = permission.get('FromPort'), permission.get('ToPort')
                        if from_port is not None and to_port is not None:
                             for port in range(from_port, to_port + 1):
                                if port in sensitive_ports:
                                    findings.append({"resource": f"{group['GroupId']} (Port {port})", "finding": "Security group has a sensitive port open to the internet.", "recommendation": "Restrict the inbound rule to a specific IP range."}); break
    except ClientError as e:
        if not quiet: print(f"  [!] Error connecting to AWS EC2: {e}.")
        return []
    if not quiet:
        print(f"  [+] Security group check complete. Found {len(findings)} potential issues.")
    return findings

def check_root_mfa(quiet=False):
    """Checks if the root user has MFA enabled."""
    if not quiet:
        print("[*] Checking for MFA on root account...")
    iam_client = boto3.client('iam')
    findings = []
    # ... (rest of the function logic is the same)
    try:
        summary = iam_client.get_account_summary()
        if summary['SummaryMap']['AccountMFAEnabled'] == 0:
            findings.append({"resource": "Root User", "finding": "Multi-Factor Authentication (MFA) is not enabled for the root user.", "recommendation": "Enable MFA for the root user immediately."})
    except ClientError as e:
        if not quiet:
            if e.response['Error']['Code'] == 'AccessDenied':
                print("  [!] Warning: Could not check for root MFA due to lack of 'iam:GetAccountSummary' permissions.")
            else:
                print(f"  [!] Error connecting to AWS IAM: {e}.")
        return []
    if not quiet:
        print(f"  [+] Root MFA check complete. Found {len(findings)} potential issues.")
    return findings


