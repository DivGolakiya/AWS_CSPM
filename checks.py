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
                # Check the Public Access Block configuration
                pub_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                config = pub_access_block['PublicAccessBlockConfiguration']
                if not (config['BlockPublicAcls'] and config['BlockPublicPolicy'] and 
                        config['IgnorePublicAcls'] and config['RestrictPublicBuckets']):
                    is_public = True
            except ClientError as e:
                # If no Public Access Block is set, it might be public via ACLs.
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    try:
                        # Check the bucket's Access Control List (ACL)
                        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                        for grant in acl['Grants']:
                            grantee = grant.get('Grantee', {})
                            uri = grantee.get('URI', '')
                            if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                                is_public = True
                                break
                    except ClientError:
                        # Handle cases where we might not have permission to get ACLs, though ReadOnlyAccess should be enough.
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


