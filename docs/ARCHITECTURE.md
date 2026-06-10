# Threat Intelligence Platform - Architecture Documentation

## Overview

The Threat Intelligence Platform is an automated cybersecurity solution that collects threat intelligence, stores indicators of compromise (IOCs), automatically enforces firewall policies, and provides monitoring and rollback capabilities.

## Architecture Components

### 1. Threat Intelligence Collection Layer

* Collects threat feeds from external sources.
* Extracts malicious IP addresses and indicators.
* Sends data to MongoDB.

### 2. Data Storage Layer

* MongoDB stores:

  * Malicious IP addresses
  * Threat levels
  * Source information
  * Timestamps
* Acts as the central threat intelligence database.

### 3. Dynamic Policy Enforcement Engine

* Python daemon continuously monitors MongoDB.
* Detects high-risk threats.
* Executes firewall rules using iptables.
* Automatically blocks malicious IP addresses.

### 4. Firewall Layer

* Uses Linux iptables.
* Drops traffic from identified malicious sources.
* Prevents further communication from blocked IPs.

### 5. Rollback Mechanism

* Allows SOC analysts to remove firewall rules.
* Handles false positives.
* Restores legitimate network access when required.

### 6. Logging and Monitoring

* Records all blocking and unblocking actions.
* Maintains audit logs for investigation and reporting.

### 7. Visualization Layer

* Kibana dashboards display:

  * Blocked IPs
  * Threat trends
  * Threat sources
  * Security events over time

## Data Flow

Threat Feed Sources
↓
Threat Collection Script
↓
MongoDB Database
↓
Policy Enforcement Engine
↓
iptables Firewall
↓
Threat Blocked

## Rollback Flow

SOC Analyst
↓
Rollback Script
↓
iptables Rule Removal
↓
Access Restored

## Technologies Used

* Python
* MongoDB
* Linux iptables
* Kibana
* GitHub
* Kali Linux

## Security Benefits

* Automated threat response
* Reduced incident response time
* Continuous monitoring
* Centralized threat management
* Analyst-controlled rollback capability
