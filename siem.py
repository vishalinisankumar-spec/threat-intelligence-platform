from pymongo import MongoClient
from datetime import datetime
import json

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intelligence"]
collection = db["threats"]

SIEM_LOG = "siem_report.json"
COMPLIANCE_LOG = "compliance_log.json"

def collect_threat_logs():
    print("Collecting threat logs from MongoDB...")
    threats = list(collection.find({}, {"_id": 0}))
    events = []
    for threat in threats:
        events.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": "MongoDB",
            "ip": threat.get("ip", "unknown"),
            "threat_type": threat.get("threat", "unknown"),
            "severity": threat.get("severity", "unknown"),
            "action": "DETECTED"
        })
    return events

def collect_compliance_logs():
    print("Collecting compliance logs...")
    try:
        with open(COMPLIANCE_LOG, "r") as f:
            logs = json.load(f)
        for log in logs:
            log["source"] = "Compliance Logger"
        return logs
    except FileNotFoundError:
        print("No compliance log found!")
        return []

def generate_siem_report():
    print("\n=============================")
    print("   SIEM REPORT GENERATION")
    print("=============================\n")

    threat_logs = collect_threat_logs()
    compliance_logs = collect_compliance_logs()

    # Combine all logs
    all_events = threat_logs + compliance_logs

    # Summary
    total = len(all_events)
    high = len([e for e in all_events if e.get("severity") == "High"])
    medium = len([e for e in all_events if e.get("severity") == "Medium"])

    report = {
        "report_generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_events": total,
            "high_severity": high,
            "medium_severity": medium
        },
        "events": all_events
    }

    # Save report
    with open(SIEM_LOG, "w") as f:
        json.dump(report, f, indent=4)

    print(f"Total Events: {total}")
    print(f"High Severity: {high}")
    print(f"Medium Severity: {medium}")
    print(f"\nSIEM Report saved to: {SIEM_LOG}")
    print("\n✅ SIEM Integration Complete!")

generate_siem_report()
