import sys
import argparse
from checks import (
    validate_credentials, get_available_regions,
    check_s3_public_access, 
    check_open_security_groups, 
    check_root_mfa,
    check_inactive_iam_keys,
    check_cloudtrail_enabled,
    check_iam_password_policy,
    check_publicly_accessible_rds
)

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
    parser.add_argument("--scan-type", choices=['quick', 'full'], default='full', help="Specify scan type: quick (single region) or full (all regions).")
    parser.add_argument("--region", help="Specify the AWS region for a 'quick' scan.")
    args = parser.parse_args()
    
    # --- VALIDATION (for local credentials) ---
    is_valid, error_message = validate_credentials(None, None)
    if not is_valid:
        print(f"[!] Credential Validation Failed: {error_message}")
        sys.exit(1)
    
    regions_to_scan = None
    if args.scan_type == 'quick':
        if not args.region:
            print("[!] Error: You must specify a region for a 'quick' scan using --region.")
            sys.exit(1)
        
        available_regions = get_available_regions(None, None)
        if args.region not in available_regions:
            print(f"[!] Error: '{args.region}' is not a valid or enabled region for this account.")
            sys.exit(1)
            
        regions_to_scan = [args.region]
        print(f"[*] Starting Quick Scan on region: {args.region}...")
    else:
        print("[*] Starting Full Scan across all regions...")

    all_findings = []
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


