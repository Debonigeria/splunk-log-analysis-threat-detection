# splunk-log-analysis-threat-detection
A Splunk-based project for log analysis, security monitoring, and automated threat detection using real-world event data

## 🎯 Objectives
- Collect and ingest FTP logs into Splunk
- Parse and normalize log data
- Detect brute-force login attempts
- Identify unauthorized access attempts
- Monitor file upload/download activities
- Create dashboards and alerts for security incidents
- Generate actionable security insights

---

## 🛠️ Technologies Used
- Splunk Enterprise / Splunk Cloud
- FTP Server Logs
- SPL (Search Processing Language)
- Windows/Linux Environment
- CSV Log Files

---

## 📂 Dataset
The project uses FTP server log files containing:

- Timestamp  
- Source IP Address  
- Username  
- Login Status  
- FTP Commands  
- File Transfer Activities  
- Session Information

### Example Log Entry

2025-01-15 10:25:32 192.168.1.50 USER admin LOGIN FAILED
2025-01-15 10:26:10 192.168.1.50 USER admin LOGIN FAILED
2025-01-15 10:27:01 192.168.1.50 USER admin LOGIN SUCCESS

---

## 📥 Log Ingestion

### Step 1: Upload Logs
1. Open Splunk Web
2. Navigate to:  
   `Settings → Add Data`
3. Upload FTP log files
4. Configure source type:

`brute force logs`

5. Index data into:

`main`

---


## 🚨 Threat Detection Use Cases

### 1. Failed Login Attempts
Detect repeated authentication failures.
```spl
index=ftp_security "LOGIN FAILED"
| stats count by src_ip
| sort - count
````

---

### 2. Brute Force Attack Detection

Identify IPs generating multiple failed logins.

```spl
index=ftp_security "LOGIN FAILED"
| stats count by src_ip
| where count > 10
```

---

### 3. Successful Login After Multiple Failures

Detect potential account compromise.

```spl
index=ftp_security
("LOGIN FAILED" OR "LOGIN SUCCESS")
| stats 
    count(eval(searchmatch("LOGIN FAILED"))) as failed_attempts
    count(eval(searchmatch("LOGIN SUCCESS"))) as successful_logins
    by src_ip username
| where failed_attempts > 5 AND successful_logins > 0
```

---

### 4. Unusual File Upload Activity

Monitor large or excessive file uploads.

```spl
index=ftp_security action=upload
| stats count sum(file_size) as total_upload_size by username
| sort - total_upload_size
```

---

### 5. Access from Suspicious IP Addresses

```spl
index=ftp_security
| stats count by src_ip
| lookup suspicious_ips ip as src_ip OUTPUT threat_level
| where threat_level="High"
```

---

## 📊 Dashboard Components

### Security Overview

* Total FTP Sessions
* Failed Logins
* Successful Logins
* File Upload Count
* File Download Count

---

## 📈 Visualizations

### Failed Logins by IP

```spl
index=ftp_security "LOGIN FAILED"
| timechart count by src_ip
```

### Login Success vs Failure

```spl
index=ftp_security
| eval status=if(searchmatch("LOGIN SUCCESS"),"Success","Failure")
| chart count over status
```

### Top Active Users

```spl
index=ftp_security
| stats count by username
| sort - count
```

---

## 🚨 Alert Configuration

### Brute Force Detection Alert

```spl
index=ftp_security "LOGIN FAILED"
| stats count by src_ip
| where count > 20
```

**Alert Settings:**

* Run every 5 minutes
* Send email notification
* Create security incident ticket

---

## 🔍 Key Findings

* Multiple failed login attempts indicate brute-force attacks
* Successful login after repeated failures may suggest compromised credentials
* Large file transfers can indicate data exfiltration
* Monitoring source IP behavior improves threat visibility
* Automated alerts reduce incident response time

---

## 🛡️ Security Recommendations

* Enforce strong password policies
* Enable Multi-Factor Authentication (MFA)
* Block suspicious IP addresses
* Monitor FTP activity continuously
* Replace FTP with secure alternatives (SFTP/FTPS)
* Configure real-time Splunk alerts

---

## 📁 Project Structure

```
Splunk-Log-Analysis-Splunk/
│
├── README.md
├── sample_logs/
│   └── brute force.log
│
├── spl_queries/
│   ├── failed_logins.spl
│   ├── brute_force_detection.spl
│   ├── file_upload_monitoring.spl
│   └── suspicious_access.spl
│
├── dashboards/
│   └── ftp_security_dashboard.xml
│
└── screenshots/
    ├── dashboard.png
    ├── alerts.png
    └── reports.png
```

---

## 🧾 Conclusion

This project demonstrates how Splunk can be used to analyze FTP logs, detect threats, and improve security monitoring. By leveraging SPL queries, dashboards, and automated alerts, organizations can proactively identify malicious activities and respond to incidents efficiently.

---

## 👤 Author

**Adebowale Oladimeji**

## 🧰 Tool

Splunk Enterprise

## 🧭 Domain

Cybersecurity / Security Operations (SOC) / Threat Detection
