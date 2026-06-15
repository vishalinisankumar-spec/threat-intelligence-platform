# Threat Intelligence Platform (TIP) & Dynamic Policy Enforcer

## Overview
Financial institutions face thousands of cyber attacks every day.
Traditional security systems are too slow and wait for humans to
manually identify and block threats. This platform solves that by
automating the entire process from detecting a threat to blocking
it in milliseconds without any human intervention.

Built as part of Cybersecurity Internship at Infotact Solutions and Co.

---

## What This Platform Does
- Collects real threats from 3 public OSINT sources
- Stores them in a MongoDB database
- Assigns a danger score from 1 to 10 to every threat
- Automatically blocks malicious IPs using iptables firewall
- Continuously monitors database every 60 seconds using a daemon
- Allows SOC analysts to reverse false positive blocks
- Sends email alerts when critical threats are detected
- Shows everything on a live SIEM dashboard
- Creates PCI-DSS compliant audit logs
- Generates a master SIEM report

---

## Project Files

### osint_fetch.py
Connects to 3 public OSINT threat feeds and collects real malicious
IPs, domains and URLs. Implements deduplication to avoid storing
duplicate threats. Sources used:
- AlienVault OTX
- VirusTotal
- Feodo Tracker

### risk_scorer.py
Assigns a risk score from 1 to 10 to every threat based on
threat type, severity level and source reliability.
- Score 9 to 10 = Critical
- Score 7 to 8 = High
- Score 5 to 6 = Medium
- Score 1 to 4 = Low

### policy_enforcer.py
Reads all malicious IPs from MongoDB and automatically creates
iptables firewall rules to block them at the network level.

### policy_daemon.py
A Python daemon that continuously monitors MongoDB every 60 seconds
for new Critical threats and automatically blocks them using iptables.
Runs 24 hours a day without stopping.

### rollback.py
A SOC analyst tool that allows reversing automated firewall rules
in case of false positives. Shows all blocked IPs and allows
instant unblocking. Updates MongoDB status to ROLLED_BACK.

### email_alert.py
Automatically sends email alerts to SOC analysts when Critical
threats are detected with full threat details and dashboard link.

### dashboard.py
A Flask based SIEM dashboard with real time search and filter
functionality showing all threats, risk levels and sources.

### compliance_logger.py
Creates immutable PCI-DSS compliant audit records of every
security event with exact timestamps and actions taken.

### siem.py
Aggregates data from all sources into one centralized master
report similar to enterprise tools like Splunk and IBM QRadar.

---

## Tech Stack
- Python 3
- MongoDB
- Flask
- iptables
- Kali Linux
- AlienVault OTX API
- VirusTotal API
- Feodo Tracker

---

## How to Run

### Install dependencies
pip install pymongo flask requests python-dotenv

### Start MongoDB
sudo service mongodb start

### Collect Threats
python3 osint_fetch.py

### Score Threats
python3 risk_scorer.py

### Block Malicious IPs
sudo python3 policy_enforcer.py

### Start Continuous Monitoring
sudo python3 policy_daemon.py

### Rollback False Positives
sudo python3 rollback.py

### Send Email Alerts
python3 email_alert.py

### Start Dashboard
python3 dashboard.py

### Generate Compliance Logs
python3 compliance_logger.py

### Generate SIEM Report
python3 siem.py

---

## Dashboard
Access at http://localhost:5000

---

## Results
- 3 OSINT sources connected
- 139 unique real threats collected
- 895 threats risk scored
- Critical threats automatically blocked
- Continuous monitoring every 60 seconds
- SOC analyst rollback mechanism working
- Email alerts sending successfully
- PCI-DSS compliant audit logs generated

---

## Compliance
This platform meets PCI-DSS requirements for financial institutions
by maintaining immutable logs of all network access and security
events with exact timestamps and actions taken.

---
Week 3: Dynamic Policy Enforcement Engine

The third phase transitioned from detection to automated defense. A Dynamic Policy Enforcement Engine was developed to continuously monitor high-risk threats and automatically enforce security policies.

Activities Completed
Developed policy_enforcer.py for automated threat blocking.
Integrated MongoDB threat database with firewall automation.
Implemented automatic IP blocking using Linux iptables.
Created policy_daemon.py to monitor threats continuously.
Configured the system to check for new threats every 60 seconds.
Automated security policy enforcement without human intervention.
Logged blocked IP addresses for future analysis.


Week 4: Alerting, Testing, and Final Reporting

The final phase focused on operational safety, monitoring, visualization, and project documentation.

Activities Completed
Implemented rollback.py to reverse firewall rules in case of false positives.
Added functionality for SOC analysts to unblock IP addresses.
Implemented email alerting for critical threats.
Finalized dashboard visualization and monitoring components.
Generated compliance and audit logs for security events.
Organized project scripts and documentation.
Performed testing and validation of all project modules.
Updated GitHub repository with scripts, documentation, and architecture diagrams.


## Project Status

This project is complete. Over four weeks I built a fully functional
Threat Intelligence Platform that connects to 3 real OSINT sources,
collects and scores threats, automatically blocks malicious IPs
through a continuous monitoring daemon, allows rollback of false
positives, sends email alerts for critical threats, and displays
everything on a live SIEM dashboard, all backed by PCI-DSS compliant
audit logging.

## Four Week Summary

### Week 1
Set up Kali Linux environment, connected to 3 OSINT sources
(AlienVault OTX, VirusTotal, Feodo Tracker), collected 139 unique
real threats, implemented deduplication and stored everything in
MongoDB.

### Week 2
Designed a risk scoring schema assigning scores from 1 to 10 based
on threat type, severity and source reliability. Built an advanced
Flask SIEM dashboard with search and filter functionality as a
lightweight alternative to ELK Stack.

### Week 3
Developed policy_daemon.py, a Python daemon that continuously
monitors MongoDB every 60 seconds and automatically blocks Critical
threats using iptables. Built rollback.py for SOC analysts to reverse
false positives, and email_alert.py to send automatic alerts for
Critical threats.

### Week 4
Updated the dashboard to show BLOCKED and ROLLED_BACK status for
every threat. Added complete architecture documentation describing
the five layer system design, data flow and database schema.
Finalized README and pushed all code to GitHub.



## Last Updated
This project was completed and finalized today as part of the
4 week cybersecurity internship at Infotact Solutions and Co.

## Author
Vishalini 
Cybersecurity Intern
Infotact Solutions .
GitHub: vishalinisankumar-spec
