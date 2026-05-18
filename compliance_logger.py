from pymongo import MongoClient
from datetime import datetime
import json
import os

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intelligence"]
collection = db["threats"]

# Log file path
LOG_FILE = "compliance_log.json"

def create_log_entry(threat):
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": threat.get("ip", "unknown"),
        "threat_type": threat.get("threat", "unknown"),
        "severity": threat.get("severity", "unknown"),
        "action": "BLOCKED",
        "compliance": "PCI-DSS"
    }

def save_logs():
    print("Starting Compliance Logger...")
    threats = list(collection.find({}, {"_id": 0}))
    
    logs = []
    for threat in threats:
        entry = create_log_entry(threat)
        logs.append(entry)
        print(f"Logged: {entry['ip']} - {entry['severity']} - {entry['timestamp']}")
    
    # Save to JSON log file
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)
    
    print(f"\nTotal logs saved: {len(logs)}")
    print(f"Log file saved to: {LOG_FILE}")

save_logs()
