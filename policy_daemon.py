import time
import subprocess
from pymongo import MongoClient
from datetime import datetime

client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intelligence"]
collection = db["threats"]

blocked_ips = set()

def block_ip(ip):
    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " BLOCKED: " + ip)
        return True
    except:
        print("Failed to block: " + ip)
        return False

def monitor_threats():
    print("Policy Daemon Started...")
    print("Monitoring every 60 seconds...")
    print("Press Ctrl+C to stop")
    print("==============================")
    while True:
        threats = collection.find({"risk_level": "Critical"})
        new_blocks = 0
        for threat in threats:
            ip = threat.get("ip", "")
            if ip and ip not in blocked_ips and not ip.startswith("http"):
                if block_ip(ip):
                    blocked_ips.add(ip)
                    new_blocks += 1
                    collection.update_one(
                        {"_id": threat["_id"]},
                        {"$set": {"status": "BLOCKED"}}
                    )
        print(datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " Scan complete. New blocks: " + str(new_blocks))
        time.sleep(60)

monitor_threats()
