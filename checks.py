import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone, timedelta

def get_boto_client(service_name, aws_access_key_id=None, aws_secret_access_key=None, region_name=None):
    """
    Creates a boto3 client, using provided credentials and region if available.
    Defaults to 'us-east-1' if no region is specified, which is crucial for cloud environments.
    """
    # Use 'us-east-1' as a fallback if no region is provided
    effective_region = region_name if region_name else 'us-east-1'

    if aws_access_key_id and aws_secret_access_key:
        return boto3.client(
            service_name,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=effective_region
        )
    return boto3.client(service_name, region_name=effective_region)

def check_s3_public_access(aws_access_key_id=None, aws_secret_access_key=None, quiet=False):
    if not quiet: print("[*] Checking for publicly accessible S3 buckets...")
    # S3 is global, so region doesn't strictly matter, but it's good practice
    s3_client = get_boto_client('s3', aws_access_key_id, aws_secret_access_key)
    findings = []
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
                        # For buckets without a PublicAccessBlock, we need to check the ACL
                        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                        for grant in acl['Grants']:
                            if 'AllUsers' in grant.get('Grantee', {}).get('URI', '') or 'AuthenticatedUsers' in grant.get('Grantee', {}).get('URI', ''):
                                is_public = True; break
                    except ClientError: pass # Ignore buckets where we can't get ACL
            if is_public:
                findings.append({ "resource": bucket_name, "finding": "S3 Bucket is potentially public.", "recommendation": "Enable all 'Block public access' settings."})
    except ClientError as e:
        if not quiet: print(f"  [!] Error connecting to AWS S3: {e}.")
        return [{"resource": "S3 Service", "finding": f"Could not access S3 buckets. Error: {e.response['Error']['Code']}", "recommendation": "Ensure credentials have s3:ListBuckets and s3:GetBucketAcl permissions."}]
    if not quiet:
        print(f"  [+] S3 check complete. Found {len(findings)} potential issues.")
    return findings

def check_open_security_groups(aws_access_key_id=None, aws_secret_access_key=None, regions_to_scan=None, quiet=False):
    if not quiet: print("[*] Checking for open security groups on sensitive ports...")
    findings = []
    sensitive_ports = [22, 3389]
    if not regions_to_scan:
        try:
            # This initial client will now correctly use 'us-east-1' by default
            ec2_client = get_boto_client('ec2', aws_access_key_id, aws_secret_access_key)
            regions_to_scan = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        except ClientError as e:
            if not quiet: print(f"  [!] Error listing AWS regions: {e}.")
            return [{"resource": "EC2 Service", "finding": f"Could not list regions. Error: {e.response['Error']['Code']}", "recommendation": "Ensure credentials have ec2:DescribeRegions permission."}]

    for region in regions_to_scan:
        try:
            regional_ec2 = get_boto_client('ec2', aws_access_key_id, aws_secret_access_key, region_name=region)
            response = regional_ec2.describe_security_groups()
            for group in response['SecurityGroups']:
                for permission in group['IpPermissions']:
                    for ip_range in permission.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port, to_port = permission.get('FromPort'), permission.get('ToPort')
                            if from_port is not None and to_port is not None:
                                for port in range(from_port, to_port + 1):
                                    if port in sensitive_ports:
                                        findings.append({"resource": f"{group['GroupId']} (Region: {region}, Port {port})", "finding": "Security group has a sensitive port open to the internet.", "recommendation": "Restrict the inbound rule to a specific IP range."}); break
        except ClientError:
            if not quiet: print(f"  [!] Warning: Could not scan region {region}. It may be disabled.")
            continue
    if not quiet:
        print(f"  [+] Security group check complete. Found {len(findings)} potential issues.")
    return findings
    
def check_root_mfa(aws_access_key_id=None, aws_secret_access_key=None, quiet=False):
    if not quiet: print("[*] Checking for MFA on root account...")
    # IAM is global, but the client still benefits from a default region
    iam_client = get_boto_client('iam', aws_access_key_id, aws_secret_access_key)
    findings = []
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
        return [{"resource": "IAM Service", "finding": f"Could not check root MFA. Error: {e.response['Error']['Code']}", "recommendation": "Ensure credentials have iam:GetAccountSummary permission."}]
    if not quiet:
        print(f"  [+] Root MFA check complete. Found {len(findings)} potential issues.")
    return findings

def check_inactive_iam_keys(aws_access_key_id=None, aws_secret_access_key=None, quiet=False):
    if not quiet: print("[*] Checking for inactive IAM access keys...")
    iam_client = get_boto_client('iam', aws_access_key_id, aws_secret_access_key)
    findings = []
    ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)
    try:
        response = iam_client.list_users()
        for user in response['Users']:
            username = user['UserName']
            keys_response = iam_client.list_access_keys(UserName=username)
            for key in keys_response['AccessKeyMetadata']:
                key_id = key['AccessKeyId']
                try:
                    last_used_response = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                    last_used_date = last_used_response['AccessKeyLastUsed'].get('LastUsedDate')
                    if last_used_date is None:
                        if key['CreateDate'] < ninety_days_ago:
                            findings.append({"resource": f"User: {username}, Key: {key_id}", "finding": "Access key has never been used and is over 90 days old.", "recommendation": "Delete the unused access key."})
                    elif last_used_date < ninety_days_ago:
                        findings.append({"resource": f"User: {username}, Key: {key_id}", "finding": "Access key has not been used in over 90 days.", "recommendation": "Rotate or delete the inactive access key."})
                except ClientError as e:
                     if not quiet and e.response['Error']['Code'] == 'AccessDenied':
                        print(f"  [!] Warning: Could not check last use for key {key_id}. Missing 'iam:GetAccessKeyLastUsed' permission.")
                     continue
    except ClientError as e:
        if not quiet: print(f"  [!] Error connecting to AWS IAM: {e}.")
        return [{"resource": "IAM Service", "finding": f"Could not list IAM users. Error: {e.response['Error']['Code']}", "recommendation": "Ensure credentials have iam:ListUsers and iam:ListAccessKeys permissions."}]
    if not quiet:
        print(f"  [+] Inactive IAM key check complete. Found {len(findings)} potential issues.")
    return findings

def check_cloudtrail_enabled(aws_access_key_id=None, aws_secret_access_key=None, quiet=False):
    if not quiet: print("[*] Checking for CloudTrail logging...")
    cloudtrail_client = get_boto_client('cloudtrail', aws_access_key_id, aws_secret_access_key)
    findings = []
    try:
        response = cloudtrail_client.describe_trails()
        active_multi_region_trail = False
        for trail in response['trailList']:
            if trail.get('IsMultiRegionTrail'):
                # We need to specify the region of the trail to check its status
                trail_region = trail['HomeRegion']
                regional_cloudtrail = get_boto_client('cloudtrail', aws_access_key_id, aws_secret_access_key, region_name=trail_region)
                trail_status = regional_cloudtrail.get_trail_status(Name=trail['TrailARN'])
                if trail_status.get('IsLogging'):
                    active_multi_region_trail = True
                    break
        if not active_multi_region_trail:
            findings.append({"resource": "AWS Account", "finding": "No active, multi-region CloudTrail trail found.", "recommendation": "Create a new CloudTrail trail that applies to all regions to ensure all API activity is logged."})
    except ClientError as e:
        if not quiet: print(f"  [!] Error connecting to AWS CloudTrail: {e}.")
        return [{"resource": "CloudTrail Service", "finding": f"Could not describe CloudTrail trails. Error: {e.response['Error']['Code']}", "recommendation": "Ensure credentials have cloudtrail:DescribeTrails and cloudtrail:GetTrailStatus permissions."}]
    if not quiet:
        print(f"  [+] CloudTrail check complete. Found {len(findings)} potential issues.")
    return findings

def check_iam_password_policy(aws_access_key_id=None, aws_secret_access_key=None, quiet=False):
    if not quiet: print("[*] Checking IAM password policy...")
    iam_client = get_boto_client('iam', aws_access_key_id, aws_secret_access_key)
    findings = []
    try:
        iam_client.get_account_password_policy()
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            findings.append({"resource": "IAM Password Policy", "finding": "No IAM password policy is configured for the account.", "recommendation": "Create a strong IAM password policy (e.g., require minimum length, uppercase, lowercase, numbers, and symbols)."})
        else:
            if not quiet: print(f"  [!] Error checking IAM password policy: {e}.")
            return [{"resource": "IAM Service", "finding": f"Could not check IAM password policy. Error: {e.response['Error']['Code']}", "recommendation": "Ensure credentials have iam:GetAccountPasswordPolicy permission."}]
    if not quiet:
        print(f"  [+] IAM password policy check complete. Found {len(findings)} potential issues.")
    return findings
    
def check_publicly_accessible_rds(aws_access_key_id=None, aws_secret_access_key=None, regions_to_scan=None, quiet=False):
    if not quiet: print("[*] Checking for publicly accessible RDS instances...")
    findings = []
    if not regions_to_scan:
        try:
            ec2_client = get_boto_client('ec2', aws_access_key_id, aws_secret_access_key)
            regions_to_scan = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        except ClientError as e:
            if not quiet: print(f"  [!] Error listing AWS regions: {e}.")
            return [{"resource": "EC2 Service", "finding": f"Could not list regions. Error: {e.response['Error']['Code']}", "recommendation": "Ensure credentials have ec2:DescribeRegions permission."}]

    for region in regions_to_scan:
        try:
            rds_client = get_boto_client('rds', aws_access_key_id, aws_secret_access_key, region_name=region)
            response = rds_client.describe_db_instances()
            for instance in response['DBInstances']:
                if instance.get('PubliclyAccessible'):
                    findings.append({"resource": f"{instance['DBInstanceIdentifier']} (Region: {region})", "finding": "RDS instance is publicly accessible.", "recommendation": "Set 'PubliclyAccessible' to false and ensure the database is in a private subnet."})
        except ClientError:
            if not quiet: print(f"  [!] Warning: Could not scan region {region}. It may be disabled.")
            continue
    if not quiet:
        print(f"  [+] Public RDS check complete. Found {len(findings)} potential issues.")
    return findings


