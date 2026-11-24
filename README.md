# Splunk Home Lab: Linux Log Ingestion, Parsing & Tier 1 SOC Triage

A hands-on home lab project focused on forwarding Linux authentication logs to **Splunk Enterprise**, extracting structured fields with SPL (`rex`), and practicing **Tier 1 (L1) SOC** alert triage, investigation, and escalation workflows[cite: 6, 8, 9, 10].

> **Note:** All attack logs and scenarios in this repository were simulated in a local home lab environment for learning and portfolio demonstration purposes.

---

## Lab Architecture & Setup

* **Log Source & Forwarder:** Kali Linux VM running **Splunk Universal Forwarder** (`/opt/splunkforwarder`)[cite: 10]
* **Indexer & Search Head:** Splunk Enterprise (`/opt/splunk`) listening for forwarder data on port **`9997`**[cite: 6]
* **Monitored Log Sources:** `/var/log/kali_test_auth.log` (simulated authentication & privilege escalation events) and `/var/log/auth.log` under `sourcetype=linux_secure`

### Key Verification Steps Performed
1. Enabled receiving on port `9997` in Splunk Enterprise (**Settings > Forwarding and receiving > Configure receiving**)[cite: 6].
2. Configured forwarding to `127.0.0.1:9997` and verified active forwarder connectivity (`Active forwards`).
3. Added log monitors with `sourcetype=linux_secure` into the `main` index and confirmed event ingestion in Splunk Search[cite: 7].

---

## Investigation Scenarios & SPL Queries

### Scenario 1: SSH Brute-Force & Successful Login (`T1110` / `T1078`)
Simulated repeated failed SSH login attempts (`Failed password`) followed by a successful authentication (`Accepted password`) from an external IP (`45.33.32.156`) against account `kali`[cite: 9].

```spl
index=main source="/var/log/kali_test_auth.log"
| rex "(?<action>Failed password|Accepted password) for (?:invalid user )?(?<target_user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| table _time, host, src_ip, target_user, action
```

### Scenario 2: Privilege Escalation, `su` Failures & Persistence (`T1548` / `T1136`)
Investigated unauthorized `sudo` attempts (`user NOT in sudoers`), failed `su` attempts (`FAILED SU`), SUID permission modification (`chmod u+s /bin/bash`), new privileged user creation (`useradd ... -G sudo sysadmin_bak`), and sensitive file access (`/etc/shadow`)[cite: 8].

```spl
index=main source="/var/log/kali_test_auth.log" ("sudo:" OR "FAILED SU")
| rex "sudo:\s+(?<actor_user>\S+)\s+:.*USER=(?<target_user>\S+)\s+;\s+COMMAND=(?<command>.*)"
| rex "sudo:\s+(?<actor_user>\S+)\s+:\s+user NOT in sudoers"
| rex "su:\s+(?<su_status>FAILED SU)\s+\(to (?<target_user>[^)]+)\)\s+(?<actor_user>\S+)"
| eval target_user=if(isnull(target_user) AND like(_raw, "%NOT in sudoers%"), "root", target_user)
| eval event_type=if(isnotnull(su_status), "Failed SU Attempt", if(like(_raw, "%NOT in sudoers%"), "Unauthorized Sudo Attempt", "Privileged Sudo Execution"))
| table _time, host, actor_user, target_user, event_type, command
```

---

## Tier 1 (L1) Triage & Escalation Summary

When reviewing structured results showing repeated failed logins followed by a successful login or suspicious privilege escalation commands[cite: 8, 9]:

1. **Quick Triage:** Check IP reputation/context, inspect post-login activity on `host=kali`, and check if the same source IP appears on other hosts.
2. **Escalation Decision:** Escalate to **Tier 2 / Incident Response** as a **True Positive** when unauthorized access or privilege escalation/persistence activity is observed.
3. **Recommended Containment (for Tier 2 / IR):**
   * Block malicious source IP at the perimeter firewall/security group.
   * Reset credentials and terminate active sessions for affected accounts (`kali`, `sysadmin_bak`).
   * Audit `/etc/passwd`, SUID binaries, cron jobs, and active network connections (`ss -tunap`).

---

## What I Learned as an Aspiring L1 SOC Analyst
* Why structured field extraction (`rex`, `table`, `stats`) is essential for fast triage instead of reading raw logs line by line[cite: 8, 9].
* How authentication, `sudo`, `su`, and account creation logs reveal attacker progression from initial access to privilege escalation and persistence[cite: 8, 9].
* How to document findings clearly for Tier 2 escalation while keeping claims honest and grounded in lab practice.

---

## Earlier SPL & Exploring SPL Practice Notes

Below are my earlier notes and queries from exploring basic Splunk search commands and SPL fundamentals prior to setting up the Kali Linux forwarder lab.

# Splunk & SIEM Log Analysis Journey

Welcome to my security log analysis repository! This repository documents my hands-on experience and query syntax learned while analyzing security logs, investigating simulated cyber incidents, and writing Splunk Processing Language (SPL) queries using **TryHackMe** interactive security labs.

---

## Objectives
- Master **Splunk Processing Language (SPL)** for threat hunting, log correlation, and anomaly detection.
- Analyze security event logs (Windows Event Logs, Sysmon, VPN Logs, Web Server Logs).
- Apply SIEM workflows, lookup enrichments, and threat detection methodologies for Tier-1 SOC Analyst roles.

---

## Key Skills & Concepts Practiced

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

## Common & Advanced SPL Snippets

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

## Completed Labs / Rooms
- [x] **Exploring SPL** (TryHackMe)

---

## 👤 Author
- **LinkedIn:** [(https://www.linkedin.com/feed/)]
- **TryHackMe:** [(https://tryhackme.com/p/touhidifarhana331)]
