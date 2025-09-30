import boto3
from checks import (
    check_s3_public_access, 
    check_open_security_groups, 
    check_root_mfa,
    check_inactive_iam_keys,
    check_cloudtrail_enabled,
    check_iam_password_policy,
    check_publicly_accessible_rds
)
import argparse

def generate_report(all_findings):
    """Generates and prints the scan report to the console."""
    print("\n" + "="*50)
    print("      AWS Security Posture Scan Report")
    print("="*50 + "\n")

    if not all_findings:
        print("[+] No security issues found. Your AWS posture looks good!")
    else:
        print(f"🚨 Found {len(all_findings)} potential security issues:\n")
        for finding in all_findings:
            print(f"  - Finding: {finding['finding']}")
            print(f"    Resource: {finding['resource']}")
            print(f"    Recommendation: {finding['recommendation']}\n")

def main():
    """Main function to run all security checks from the CLI."""
    parser = argparse.ArgumentParser(description="AWS Cloud Security Posture Manager (CSPM)")
    parser.add_argument("--scan-type", choices=['quick', 'full'], default='full', help="Specify scan type: quick (single region) or full (all regions). Default is full.")
    parser.add_argument("--region", default='us-east-1', help="Specify the AWS region for a 'quick' scan. Default is us-east-1.")
    args = parser.parse_args()

    all_findings = []
    
    regions_to_scan = None
    if args.scan_type == 'quick':
        regions_to_scan = [args.region]
        print(f"[*] Starting Quick Scan on region: {args.region}...")
    else:
        print("[*] Starting Full Scan across all regions...")

    all_findings.extend(check_s3_public_access())
    all_findings.extend(check_root_mfa())
    all_findings.extend(check_inactive_iam_keys())
    all_findings.extend(check_cloudtrail_enabled())
    all_findings.extend(check_iam_password_policy())
    
    all_findings.extend(check_open_security_groups(regions_to_scan=regions_to_scan))
    all_findings.extend(check_publicly_accessible_rds(regions_to_scan=regions_to_scan))
    
    generate_report(all_findings)

if __name__ == "__main__":
    main()


