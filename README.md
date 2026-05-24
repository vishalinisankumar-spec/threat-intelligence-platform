# Threat Intelligence Platform (TIP)

## Overview
An advanced cybersecurity platform for Finance and Banking sector
that automatically collects, analyzes, and responds to cyber threats
in real time.

Built as part of Cybersecurity Internship at Infotact Solutions and Co.

## Features
- OSINT Threat Aggregation from 3 sources
- Automatic IP blocking using iptables
- Real time SIEM Dashboard
- Risk Scoring System (1-10)
- PCI-DSS Compliance Logging
- Centralized SIEM Report

## Tech Stack
- Python 3
- MongoDB
- Flask
- iptables
- Kali Linux

## Project Files
- osint_fetch.py — Collects threats from OSINT feeds
- risk_scorer.py — Assigns risk scores to threats
- policy_enforcer.py — Blocks malicious IPs
- dashboard.py — Flask SIEM dashboard
- compliance_logger.py — PCI-DSS audit logs
- siem.py — Master SIEM report

## OSINT Sources
- AlienVault OTX
- VirusTotal
- Feodo Tracker

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

### Start Dashboard
python3 dashboard.py

### Generate Compliance Logs
python3 compliance_logger.py

### Generate SIEM Report
python3 siem.py

## Dashboard
Access at http://localhost:5000

## Results
- 3 OSINT sources connected
- 139 unique threats collected
- 302 threats risk scored
- 301 Critical threats identified
- PCI-DSS compliant audit logs

## Compliance
Meets PCI-DSS requirements for financial institutions
with immutable audit logs of all security events.

## Author
Vishalini Sankumar
Cybersecurity Intern at Infotact Solutions and Co.
