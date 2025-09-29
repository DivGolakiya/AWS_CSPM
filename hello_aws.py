import boto3
from botocore.exceptions import ClientError

def test_aws_connection():
    """
    Connects to AWS and lists S3 buckets to verify credentials.
    """
    print("Attempting to connect to AWS...")
    try:
        s3_client = boto3.client('s3')
        response = s3_client.list_buckets()
        
        print("[+] Connection Successful!")
        print("Your S3 Buckets:")
        if not response['Buckets']:
            print("  - No buckets found.")
        else:
            for bucket in response['Buckets']:
                print(f"  - {bucket['Name']}")
                
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            print("[!] Connection Failed: The AWS access key ID does not appear to be valid.")
        else:
            print(f"[!] An error occurred: {e}")

if __name__ == "__main__":
    test_aws_connection()

