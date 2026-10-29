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
```spl
index=windowslogs EventID=1
| table _time ParentProcessId ProcessId ParentCommandLine CommandLine
| reverse
