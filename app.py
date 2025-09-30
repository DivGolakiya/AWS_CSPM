import streamlit as st
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

# ... (CHECK_DESCRIPTIONS dictionary remains the same) ...
CHECK_DESCRIPTIONS = {
    "S3 Public Access": {
        "description": "Scans all S3 buckets for configurations that allow public access, a common source of data breaches.",
        "risk": "High"
    },
    "Open Security Groups": {
        "description": "Looks for security groups allowing unrestricted internet access (0.0.0.0/0) to sensitive ports like SSH (22) or RDP (3389).",
        "risk": "Critical"
    },
    "Root Account MFA": {
        "description": "Verifies that the account's root user has Multi-Factor Authentication (MFA) enabled to prevent account takeover.",
        "risk": "Critical"
    },
    "Inactive IAM Keys": {
        "description": "Scans for IAM user access keys that have not been used in over 90 days. Old, unused keys are a security liability.",
        "risk": "Medium"
    },
    "CloudTrail Enabled": {
        "description": "Ensures AWS CloudTrail is enabled across all regions to provide a complete audit log of all account activity.",
        "risk": "High"
    },
    "IAM Password Policy": {
        "description": "Verifies that a strong password policy (requiring length, complexity, etc.) is enforced for all IAM users.",
        "risk": "Medium"
    },
    "Publicly Accessible RDS": {
        "description": "Scans for any RDS database instances that are publicly accessible, which makes them a direct target for attackers.",
        "risk": "Critical"
    }
}


def run_all_checks(aws_access_key_id, aws_secret_access_key, scan_type, region):
    """Runs all security checks using the provided credentials and scan type."""
    scan_results = []
    
    # Determine which regions to scan
    regions_to_scan = None # None means scan all
    if scan_type == 'quick':
        regions_to_scan = [region]

    # Non-regional checks
    non_regional_checks = [
        ("S3 Public Access", check_s3_public_access),
        ("Root Account MFA", check_root_mfa),
        ("Inactive IAM Keys", check_inactive_iam_keys),
        ("CloudTrail Enabled", check_cloudtrail_enabled),
        ("IAM Password Policy", check_iam_password_policy)
    ]
    # Regional checks
    regional_checks = [
        ("Open Security Groups", check_open_security_groups),
        ("Publicly Accessible RDS", check_publicly_accessible_rds)
    ]

    for check_name, check_function in non_regional_checks:
        findings = check_function(aws_access_key_id, aws_secret_access_key, quiet=True)
        scan_results.append({"check_name": check_name, "findings": findings})
        
    for check_name, check_function in regional_checks:
        findings = check_function(aws_access_key_id, aws_secret_access_key, regions_to_scan=regions_to_scan, quiet=True)
        scan_results.append({"check_name": check_name, "findings": findings})

    return scan_results


def main():
    st.set_page_config(page_title="AWS CSPM Scanner", page_icon="🛡️", layout="wide")
    st.title("🛡️ AWS Cloud Security Posture Manager")
    st.write("This tool scans an AWS account for common security misconfigurations.")

    st.subheader("Enter AWS Credentials")
    st.warning(
        "**Security Warning:** Your credentials are used only for this session to run read-only checks and are not stored. For this tool to work, provide keys for an IAM user with the `ReadOnlyAccess` and `iam:GetAccountSummary` permissions. Never use your root credentials.", 
        icon="⚠️"
    )
    aws_access_key_id = st.text_input("AWS Access Key ID", type="password")
    aws_secret_access_key = st.text_input("AWS Secret Access Key", type="password")

    # --- NEW: Scan Type Selection ---
    st.subheader("Select Scan Options")
    scan_type_option = st.radio("Scan Type", ["Quick Scan (Single Region)", "Full Scan (All Regions)"], index=0)
    
    region = None
    if "Quick Scan" in scan_type_option:
        scan_type = 'quick'
        region = st.text_input("AWS Region", "us-east-1", help="Specify the single AWS region to scan for regional resources like EC2 and RDS.")
    else:
        scan_type = 'full'
        st.info("A full scan is more thorough but may take several minutes to complete as it checks all available AWS regions.", icon="ℹ️")


    if st.button("Run Security Scan", type="primary"):
        if not aws_access_key_id or not aws_secret_access_key:
            st.error("Please provide both an Access Key ID and a Secret Access Key.")
        else:
            with st.spinner("Scanning AWS environment... This may take a moment."):
                scan_results = run_all_checks(aws_access_key_id, aws_secret_access_key, scan_type, region)

            st.divider()
            st.header("Scan Report")
            total_findings = sum(len(result['findings']) for result in scan_results)

            if total_findings == 0:
                st.success("✅ No security issues found. Your AWS posture looks good!")
            else:
                st.error(f"🚨 Found {total_findings} potential security issues.")

            for result in scan_results:
                check_name = result['check_name']
                findings = result['findings']
                description_info = CHECK_DESCRIPTIONS.get(check_name, {})

                if not findings:
                    with st.expander(f"✅ **{check_name}:** Pass", expanded=False):
                        st.write(f"**Description:** {description_info.get('description', 'No description available.')}")
                        st.success("No issues found for this check.")
                else:
                    with st.expander(f"🚨 **{check_name}:** Fail ({len(findings)} issues found)", expanded=True):
                        st.write(f"**Description:** {description_info.get('description', 'No description available.')}")
                        st.write("---")
                        for finding in findings:
                            st.write(f"**Finding:** {finding['finding']}")
                            st.write(f"**Resource:** `{finding['resource']}`")
                            st.write(f"**Recommendation:** {finding['recommendation']}")
                            st.write("---")

if __name__ == "__main__":
    main()


