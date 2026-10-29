# 🔍 Splunk & SIEM Log Analysis Journey

Welcome to my security log analysis repository! This repository documents my hands-on experience and query syntax learned while analyzing security logs, investigating simulated cyber incidents, and writing Splunk Processing Language (SPL) queries using **TryHackMe** interactive security labs.

---

## 🎯 Objectives
- Master **Splunk Processing Language (SPL)** for threat hunting, log correlation, and anomaly detection.
- Analyze security event logs (Windows Event Logs, Sysmon, VPN Logs, Web Server Logs).
- Apply SIEM workflows, lookup enrichments, and threat detection methodologies for Tier-1 SOC Analyst roles.

---

## 🛠️ Key Skills & Concepts Practiced

### 1. Splunk Basics & Log Navigation
- Understanding Splunk Architecture, Indices, Sources, and Sourcetypes.
- Filtering logs using search operators and time-frame boundaries.

### 2. SPL Query Fundamentals
- **Filtering & Matching:** Wildcards, boolean logic (`AND`, `OR`, `NOT`).
- **Data Transformation:** `table`, `fields`, `rename`, `dedup`, `sort`, `reverse`.
- **Statistical Aggregation:** `stats count`, `dc()` (distinct count), `avg()`, `values()` grouped by fields (e.g., `by src_ip`).
- **Advanced Evaluation & Enrichment:** `eventstats`, `eval`, `where`, and `lookup` tables.
- **Visualization Commands:** `top`, `rare`, `chart`, `timechart`.

---

## 📝 Common & Advanced SPL Snippets

### 1. Process Execution Lineage (Sysmon Event ID 1)
Trace process creation logs to analyze parent-child process behaviors in chronological order:
` ` `spl
index=windowslogs EventID=1
| table _time ParentProcessId ProcessId ParentCommandLine CommandLine
| reverse
` ` `

### 2. Threat Intelligence / Enrichment using Lookup Tables
Map process images with threat intelligence risk scores using external lookup tables:
` ` `spl
index=windowslogs
| lookup image_riskscore Image OUTPUT RiskScore
| stats count by Image RiskScore
| sort - RiskScore
` ` `

### 3. Statistical Anomaly Detection (Rare Location Login)
Calculate user login ratios by country using `eventstats` to detect abnormal or rare access patterns (< 10% frequency):
` ` `spl
index=vpnlogs
| eventstats count as logins_by_user by user 
| eventstats count as logins_by_user_country by user src_country 
| eval country_freq=logins_by_user_country/logins_by_user
| where country_freq < 0.1
| table _time user src_ip src_country country_freq
` ` `

### 4. Top Failed Logon Events (Windows Event ID 4625)
Identify brute-force attempts by aggregating failed logon occurrences:
` ` `spl
index=win_eventlogs EventCode=4625
| stats count by TargetUserName, WorkstationName
| sort - count
` ` `

---

## 📜 Completed Labs / Rooms
- [x] **Exploring SPL** (TryHackMe)

---

## 👤 Author
- **LinkedIn:** [(https://www.linkedin.com/feed/)]
- **TryHackMe:** [(https://tryhackme.com/p/touhidifarhana331)]
