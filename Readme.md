# AWS GuardDuty Log Analysis using Splunk 🔐☁️

![Project Banner](https://github.com/user-attachments/assets/da337137-1ef1-4ba6-a3c5-6d55e241abf4)
![Project Banner](https://github.com/user-attachments/assets/4e7e110e-1f11-4d01-94dc-9aad81cdd0d7)

A hands-on **SOC-style cloud threat detection project** by **Praharsh Kumar** that shows how to ingest **AWS GuardDuty findings (JSON logs)** into **Splunk Enterprise** and investigate suspicious cloud activity.

This project focuses on simple and practical cloud security analysis for beginner SOC learning.

---

## 📌 Project Overview

**AWS GuardDuty** is an AWS security service that detects suspicious or malicious activity in AWS accounts and workloads.

In this project, I used sample GuardDuty findings and loaded them into **Splunk Enterprise** to analyze the alerts and understand what kind of attack or suspicious behavior was happening.

This project was built to follow a **fresher-friendly SOC investigation approach**:
- First identify the alert.
- Then check the source IP.
- Then check the affected AWS resource.
- Then understand the severity.
- Finally, decide the response action.

---

## 🎯 Objective

The main objective of this project is to learn how cloud threats can be detected and investigated in Splunk.

### What I wanted to do:
- Upload GuardDuty JSON findings into Splunk.
- Parse the JSON data properly.
- Detect common cloud attack patterns.
- Find attacker IPs and affected resources.
- Practice basic SOC-style log investigation.

---

## 🛠️ Tools & Technologies Used

- **Amazon GuardDuty** – source of threat findings.
- **Splunk Enterprise** – used for log analysis.
- **JSON log file** – `guardduty_findings.json`
- **SPL** – Splunk Search Processing Language.
- **spath** – used to extract nested JSON fields.

---

## 🧠 What is AWS GuardDuty?

AWS GuardDuty is a cloud threat detection service.

It monitors:
- **VPC Flow Logs** → network traffic.
- **CloudTrail Logs** → AWS API activity.
- **DNS Logs** → suspicious domain lookups.

It uses machine learning, threat intelligence, and anomaly detection to generate findings in JSON format.

---

## 🚨 Threat Categories Covered

| Finding Type | Category | Description | Severity |
|---|---|---|---|
| `UnauthorizedAccess:EC2/SSHBruteForce` | Unauthorized Access | Repeated SSH brute-force attempts on EC2. | Medium |
| `Recon:EC2/Portscan` | Reconnaissance | External IP scanning EC2 for open ports. | Low |
| `IAMUser/MaliciousIPCaller.Custom` | Suspicious API | IAM API calls from malicious IPs. | Medium |
| `CryptoCurrency:EC2/BitcoinTool.B!DNS` | Malware / Crypto | EC2 contacting crypto-mining pools. | High |
| `S3/BucketAnonymousAccessGranted` | Misconfiguration | S3 bucket publicly accessible. | Medium |

---

## 📂 Project Structure

```bash
AWS-GuardDuty-Log-Analysis-using-Splunk/
│
├── README.md
├── guardduty_findings.json
├── AWS GuardDuty Log Analysis using Splunk Project ScreenShots.pdf
```

> **Tip:** Keep screenshots in a `screenshots/` folder for a better GitHub project page.

---

## ⚙️ Splunk Setup & Data Ingestion

### Step 1: Open Splunk
Go to:

**Splunk Web → Settings → Add Data**

### Step 2: Choose Upload
Select the **Upload** option to import the local JSON file.

### Step 3: Upload the GuardDuty Log File
Upload:

```bash
guardduty_findings.json
```

### Step 4: Set Source Type
Set:

```bash
sourcetype = _json
```

### Step 5: Create / Select Index
Create and use:

```bash
guardduty_lab
```

### Step 6: Submit and Validate
After ingestion, verify the data using:

```spl
index=guardduty_lab | head 5
```

---

## 🔍 Investigation Approach

I followed a simple SOC-style method:

1. Check the finding type.
2. Identify the source IP.
3. Check the affected AWS resource.
4. Review severity.
5. Understand the timeline.
6. Decide the likely response.

This makes the investigation easy to follow and useful for beginners.

---

## 1️⃣ Brute Force Attempts (EC2 & IAM Console)

### What I checked
I looked for repeated SSH login attempts or IAM console brute-force attempts.

### SPL Query
```spl
index=guardduty_lab (type="UnauthorizedAccess:EC2/SSHBruteForce" OR type="UnauthorizedAccess:IAMUser/ConsoleLoginBruteForce")
| stats count AS attempts by resource.instanceDetails.instanceId, service.action.remoteIpDetails.ipAddressV4, region, severity
| sort -attempts
```

### What this means
If the same IP shows many attempts, it may be a brute force attack.

---

## 2️⃣ Reconnaissance (Port Probes & Port Scans)

### What I checked
I looked for port scan or port probe activity against EC2 instances.

### SPL Query
```spl
index=guardduty_lab (type="Recon:EC2/Portscan" OR type="Recon:EC2/PortProbeUnprotectedPort")
| stats count AS hits by resource.instanceDetails.instanceId, service.action.remoteIpDetails.ipAddressV4, service.action.remoteIpDetails.country
| sort -hits
```

### What this means
If one IP scans many ports, it may be recon activity before an attack.

---

## 3️⃣ Suspicious API Calls (IAM Abuse)

### What I checked
I looked for suspicious IAM API activity from unknown or bad IPs.

### SPL Query
```spl
index=guardduty_lab (type="IAMUser/MaliciousIPCaller.Custom" OR type="IAMUser/UnauthorizedAccess")
| stats count AS calls by resource.resourceType, service.action.remoteIpDetails.ipAddressV4, region, accountId
| sort -calls
```

### What this means
This can point to stolen credentials or unauthorized AWS access.

---

## 4️⃣ Crypto Mining & Malware Activity

### What I checked
I looked for signs of malware, DNS exfiltration, or crypto mining.

### SPL Query
```spl
index=guardduty_lab (type="CryptoCurrency:EC2/BitcoinTool.B!DNS" OR type="Trojan:EC2/DNSDataExfiltration" OR type="Backdoor:EC2/C&CActivity.B")
| stats count AS detections by resource.instanceDetails.instanceId, service.action.remoteIpDetails.ipAddressV4, severity
| sort -detections
```

### What this means
A high severity result here may indicate that the EC2 instance is compromised.

---

## 5️⃣ S3 Misconfigurations & Malicious Access

### What I checked
I looked for public S3 buckets or suspicious access to S3 resources.

### SPL Query
```spl
index=guardduty_lab (type="S3/MaliciousIPCaller" OR type="S3/BucketAnonymousAccessGranted")
| stats count AS findings by resource.resourceType, resource.instanceDetails.instanceId, service.action.remoteIpDetails.ipAddressV4, region
| sort -findings
```

### What this means
Public S3 buckets can cause data leaks and data exposure.

---

## 🧩 Nested JSON Fields with `spath`

GuardDuty logs contain nested JSON fields.  
To extract them clearly, I used `spath`.

### Example
```spl
index=guardduty_lab
| spath path=service.action.remoteIpDetails.ipAddressV4 output=src_ip
| spath path=resource.instanceDetails.instanceId output=instance_id
| table _time type src_ip instance_id severity region
```

### Why this helps
It makes the JSON data easier to read and investigate.

---

## 📊 Key Findings

From this project, I learned how to:
- detect brute-force attacks,
- identify port scans,
- spot suspicious IAM/API activity,
- recognize crypto mining or malware behavior,
- and find S3 exposure issues.

---

## 🛡️ Incident Response Recommendations

### For Brute Force Attacks
- Block the attacker IP.
- Disable password-based SSH login.
- Enforce MFA.
- Rotate credentials.

### For Port Scanning
- Close unused ports.
- Harden security groups.
- Limit exposed services.

### For Suspicious IAM/API Calls
- Review CloudTrail.
- Revoke suspicious credentials.
- Apply least privilege.

### For Crypto Mining / Malware
- Isolate the EC2 instance.
- Inspect DNS activity.
- Rebuild the instance if needed.

### For S3 Misconfigurations
- Remove public access.
- Enable Block Public Access.
- Review bucket policies.

---

## 🚀 How to Reproduce This Project

### 1. Install Splunk Enterprise
Set up Splunk on your system.

### 2. Download GuardDuty Findings
Use the JSON file:

```bash
guardduty_findings.json
```

### 3. Upload the File
- Go to **Settings → Add Data**
- Choose **Upload**
- Select the JSON file
- Set:
  - `sourcetype = _json`
  - `index = guardduty_lab`

### 4. Validate the Data
```spl
index=guardduty_lab | head 5
```

### 5. Run the Detection Queries
Use the SPL queries from the investigation section above.

---

## 💡 Skills Demonstrated

- Cloud Security Monitoring
- AWS GuardDuty Analysis
- Splunk Log Ingestion
- SPL Query Writing
- JSON Field Parsing
- SOC Threat Hunting
- Security Triage
- Incident Response Thinking
- Blue Team Workflow

---

## 🎓 Learning Outcomes

After completing this project, I understood:
- how GuardDuty alerts work,
- how to analyze cloud logs in Splunk,
- how to write basic detection queries,
- and how a SOC analyst investigates cloud threats.

---

## 📌 Use Cases / Real-World Relevance

This project is relevant for:
- SOC Analyst
- Cloud Security Analyst
- Cybersecurity Analyst
- Detection Engineer
- Blue Team Intern / Associate
- Splunk Security Analyst

---

## 🔮 Future Enhancements

In the future, I can improve this project by:
- creating a Splunk dashboard,
- adding alert rules,
- correlating with CloudTrail and VPC Flow Logs,
- and mapping findings to MITRE ATT&CK.

---

## 📚 References

- AWS GuardDuty Documentation
- Splunk Enterprise Documentation
- Splunk SPL Search Reference

---

## 📜 License

This project is for educational and portfolio purposes.
