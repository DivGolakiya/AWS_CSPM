import streamlit as st
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

CHECK_DESCRIPTIONS = {
    "S3 Public Access": {
        "description": "This check scans all S3 buckets to determine if any are configured to allow public access. Publicly accessible buckets can lead to unintentional data exposure and are a common source of data breaches.",
        "risk": "High"
    },
    "Open Security Groups": {
        "description": "This check looks for network security groups that allow unrestricted access (from 0.0.0.0/0) to sensitive management ports like SSH (22) and RDP (3389). Exposing these ports to the entire internet makes servers vulnerable to brute-force attacks and automated exploits.",
        "risk": "Critical"
    },
    "Root Account MFA": {
        "description": "This check verifies that the account's root user has Multi-Factor Authentication (MFA) enabled. The root user has complete control over an AWS account, and protecting it with MFA is the single most important security step to prevent a total account takeover.",
        "risk": "Critical"
    },
    "Inactive IAM Keys": {
        "description": "This check scans for IAM user access keys that have not been used in over 90 days. Old, forgotten keys are a security liability; if compromised, they provide a 'ghost' entry point into your account.",
        "risk": "Medium"
    },
    "CloudTrail Enabled": {
        "description": "This check ensures that AWS CloudTrail is enabled and actively logging API calls across all regions. CloudTrail is the primary audit log for your account; without it, you have no way to investigate security incidents or unauthorized activity.",
        "risk": "High"
    },
    "IAM Password Policy": {
        "description": "This check verifies that a strong password policy is enforced for IAM users. A strong policy (requiring length, complexity, etc.) is a fundamental defense against weak or easily guessable passwords.",
        "risk": "Medium"
    },
    "Publicly Accessible RDS": {
        "description": "This check scans for any RDS database instances that are configured to be publicly accessible from the internet. Databases should almost always be isolated in a private network, as public exposure makes them a direct target for attackers.",
        "risk": "Critical"
    }
}

def run_all_checks(aws_access_key_id, aws_secret_access_key, scan_type, region):
    scan_results = []
    regions_to_scan = [region] if scan_type == 'quick' else None
    
    check_functions = [
        ("S3 Public Access", check_s3_public_access),
        ("Root Account MFA", check_root_mfa),
        ("Inactive IAM Keys", check_inactive_iam_keys),
        ("CloudTrail Enabled", check_cloudtrail_enabled),
        ("IAM Password Policy", check_iam_password_policy)
    ]
    regional_check_functions = [
        ("Open Security Groups", check_open_security_groups),
        ("Publicly Accessible RDS", check_publicly_accessible_rds)
    ]

    for name, func in check_functions:
        findings = func(aws_access_key_id, aws_secret_access_key, quiet=True)
        scan_results.append({"check_name": name, "findings": findings})
        
    for name, func in regional_check_functions:
        findings = func(aws_access_key_id, aws_secret_access_key, regions_to_scan=regions_to_scan, quiet=True)
        scan_results.append({"check_name": name, "findings": findings})

    return scan_results

def main():
    st.set_page_config(page_title="AWS CSPM Scanner", page_icon="🛡️", layout="wide")
    st.title("🛡️ AWS Cloud Security Posture Manager")
    st.write("This tool scans an AWS account for common security misconfigurations.")

    st.subheader("Enter AWS Credentials")
    st.warning("**Security Note:** Provide keys for an IAM user with `ReadOnlyAccess`, `iam:GetAccountSummary`, and `ec2:DescribeRegions` permissions.", icon="⚠️")
    aws_access_key_id = st.text_input("AWS Access Key ID", type="password")
    aws_secret_access_key = st.text_input("AWS Secret Access Key", type="password")

    st.subheader("Select Scan Options")
    scan_type_option = st.radio("Scan Type", ["Quick Scan (Single Region)", "Full Scan (All Regions)"])
    
    region = None
    if "Quick Scan" in scan_type_option:
        scan_type = 'quick'
        region = st.text_input("AWS Region", "us-east-1")
    else:
        scan_type = 'full'
        st.info("A full scan is more thorough and may take several minutes to complete.", icon="ℹ️")

    if st.button("Run Security Scan", type="primary"):
        if not aws_access_key_id or not aws_secret_access_key:
            st.error("Please provide both an Access Key ID and a Secret Access Key.")
            return

        # --- PRE-FLIGHT VALIDATION ---
        is_valid, error_message = validate_credentials(aws_access_key_id, aws_secret_access_key)
        if not is_valid:
            st.error(f"Credential Validation Failed: {error_message}")
            return
            
        if scan_type == 'quick':
            available_regions = get_available_regions(aws_access_key_id, aws_secret_access_key)
            if region not in available_regions:
                st.error(f"Region Validation Failed: '{region}' is not a valid or enabled region for this account.")
                return

        with st.spinner("Scanning AWS environment... This may take a moment."):
            scan_results = run_all_checks(aws_access_key_id, aws_secret_access_key, scan_type, region)

        st.divider()
        st.header("Scan Report")
        total_findings = sum(len(result['findings']) for result in scan_results)

        if total_findings == 0:
            st.success("✅ No security issues found!")
        else:
            st.error(f"🚨 Found {total_findings} potential security issues.")

        for result in scan_results:
            check_name = result['check_name']
            findings = result['findings']
            description_info = CHECK_DESCRIPTIONS.get(check_name, {})
            
            if not findings:
                with st.expander(f"✅ **{check_name}:** Pass", expanded=False):
                    st.write(f"**Description:** {description_info.get('description')}")
                    st.success("No issues found for this check.")
            else:
                with st.expander(f"🚨 **{check_name}:** Fail ({len(findings)} found)", expanded=True):
                    st.write(f"**Description:** {description_info.get('description')}")
                    st.write("---")
                    for finding in findings:
                        st.write(f"**Finding:** {finding['finding']}")
                        st.write(f"**Resource:** `{finding['resource']}`")
                        st.write(f"**Recommendation:** {finding['recommendation']}")
                        st.write("---")

if __name__ == "__main__":
    main()


