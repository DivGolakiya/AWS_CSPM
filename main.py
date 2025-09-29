from checks import check_s3_public_access

def generate_report(all_findings):
    """Generates and prints a report from all findings."""
    print("\n" + "="*50)
    print("      AWS Security Posture Scan Report")
    print("="*50 + "\n")

    if not all_findings:
        print("[+] No security issues found. Your AWS posture looks good!")
        return

    for finding in all_findings:
        print(f"[!] Finding: {finding['finding']}")
        print(f"    - Resource: {finding['resource']}")
        print(f"    - Recommendation: {finding['recommendation']}\n")

def main():
    """Main function to run all security checks."""
    all_findings = []
    
    # We will add more checks here in the future
    all_findings.extend(check_s3_public_access())
    
    # Generate the final report
    generate_report(all_findings)

if __name__ == "__main__":
    main()


