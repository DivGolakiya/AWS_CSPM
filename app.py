import streamlit as st
from checks import check_s3_public_access, check_open_security_groups, check_root_mfa

def main():
    """Main function for the Streamlit web application."""
    st.set_page_config(page_title="AWS CSPM Scanner", page_icon="🛡️", layout="wide")
    st.title("🛡️ AWS Cloud Security Posture Manager")
    st.write("This tool scans your AWS account for common security misconfigurations using your configured credentials.")

    if st.button("Run Security Scan", type="primary"):
        all_findings = []
        
        with st.spinner("Scanning your AWS environment... This may take a moment."):
            # NEW: Call the check functions in quiet mode
            all_findings.extend(check_s3_public_access(quiet=True))
            all_findings.extend(check_open_security_groups(quiet=True))
            all_findings.extend(check_root_mfa(quiet=True))

        st.divider()
        st.header("Scan Report")

        if not all_findings:
            st.success("✅ No security issues found. Your AWS posture looks good!")
        else:
            st.error(f"🚨 Found {len(all_findings)} potential security issues.")
            for finding in all_findings:
                with st.container(border=True):
                    st.write(f"**Finding:** {finding['finding']}")
                    st.write(f"**Resource:** `{finding['resource']}`")
                    st.write(f"**Recommendation:** {finding['recommendation']}")

if __name__ == "__main__":
    main()


