from checks import (
    check_s3_public_access, 
    check_open_security_groups, 
    check_root_mfa,
    check_inactive_iam_keys,
    check_cloudtrail_enabled,
    check_iam_password_policy,
    check_publicly_accessible_rds
)

def generate_report(scan_results):
    """Prints a formatted, detailed report to the console."""
    print("\n" + "="*50)
    print("      AWS Security Posture Scan Report")
    print("="*50 + "\n")

    total_findings = sum(len(result['findings']) for result in scan_results)

    if total_findings == 0:
        print("[+] No security issues found. Your AWS posture looks good!")
    else:
        print(f"🚨 Found {total_findings} potential security issues.\n")

    for result in scan_results:
        status = "✅ PASS" if not result['findings'] else f"🚨 FAIL ({len(result['findings'])} issues)"
        print(f"[{status}] - {result['check_name']}")
        for finding in result['findings']:
            print(f"  - Finding: {finding['finding']}")
            print(f"    Resource: {finding['resource']}")
            print(f"    Recommendation: {finding['recommendation']}\n")


def main():
    """Main function to run all security checks for the CLI."""
    
    # A list of all checks to perform, with their display names
    all_checks = [
        ("S3 Public Access", check_s3_public_access),
        ("Open Security Groups", check_open_security_groups),
        ("Root Account MFA", check_root_mfa),
        ("Inactive IAM Keys", check_inactive_iam_keys),
        ("CloudTrail Enabled", check_cloudtrail_enabled),
        ("IAM Password Policy", check_iam_password_policy),
        ("Publicly Accessible RDS", check_publicly_accessible_rds)
    ]
    
    scan_results = []

    for check_name, check_function in all_checks:
        print(f"[*] Running check: {check_name}...")
        findings = check_function(quiet=True) # Run in quiet mode to control output
        scan_results.append({
            "check_name": check_name,
            "findings": findings
        })

    generate_report(scan_results)

if __name__ == "__main__":
    main()


