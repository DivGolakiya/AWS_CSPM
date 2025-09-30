# 🛡️ AWS Cloud Security Posture Manager (CSPM)
A Python-based tool designed to automatically scan an AWS account for common security misconfigurations and generate a comprehensive security report. The project features a modular architecture, a professional command-line interface, and an interactive web application built with Streamlit.

---
## Demo

---
## Key Features & Security Checks
This tool scans for a variety of critical security misconfigurations across your AWS environment:

* **S3 Public Access:** Detects Amazon S3 buckets that are accidentally exposed to the public.

* **Open Security Groups:** Scans for network security groups that allow unrestricted internet access (0.0.0.0/0) to sensitive ports like SSH (22) and RDP (3389).

* **Root Account MFA:** Verifies that the account's root user has Multi-Factor Authentication (MFA) enabled.

* **Inactive IAM Keys:** Identifies IAM user access keys that have not been used in over 90 days, which are a common security liability.

* **CloudTrail Enabled:** Ensures that a multi-region CloudTrail is active and logging all API activity for auditing and incident response.

* **IAM Password Policy:** Checks if a strong password policy is enforced for IAM users.

* **Publicly Accessible RDS:** Scans for any RDS database instances that are publicly accessible from the internet.
  
---
## User-Friendly Interface
The project includes two interfaces:

* **Web Application:** A clean and interactive UI built with Streamlit that allows users to securely input their credentials and choose between a "Quick Scan" (single region) or a "Full Scan" (all regions).

* **Command-Line Interface:** A fully functional CLI for terminal-based analysis, also with "Quick" and "Full" scan options.

---
## Technology Stack
* **Language:** Python 3

* **Core Libraries:**

    * boto3: The AWS SDK for Python, used to interact with the AWS API.

    * streamlit: For the interactive web application.

    * argparse: For creating the professional command-line interface.

## Setup and Usage
### Prerequisites
* Python 3.10+
* An AWS account.
* An IAM User with ReadOnlyAccess and iam:GetAccountSummary permissions.

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd AWS_CSPM
```

### 2. Set Up the Environment
Create and activate a Python virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate

Install the required dependencies:

pip install -r requirements.txt
```

### 3. Run the Application
You can run either the web application or the command-line tool.

**To run the Streamlit Web App:**
```bash
streamlit run app.py
```
The web app will prompt you for temporary AWS credentials.

**To run the Command-Line Interface (CLI):**

The CLI uses the credentials you have configured locally with the AWS CLI (aws configure).
```bash
python main.py
```

---

## Run a full scan across all regions
```bash
python main.py --scan-type full
```

## Run a quick scan on a specific region
```bash
python main.py --scan-type quick --region us-west-2
```

---

## Project Structure
The project is organized into modular files for better readability and maintenance:
```
AWS_CSPM/
├── app.py              # Main Streamlit web application
├── main.py             # Command-Line Interface (CLI)
├── checks.py           # All individual security check functions
├── requirements.txt    # Project dependencies
└── cspm_screenshot.png # Demo image for the README
```
