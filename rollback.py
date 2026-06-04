import subprocess
from pymongo import MongoClient
from datetime import datetime

client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intelligence"]
collection = db["threats"]

def show_blocked_ips():
    print("==============================")
    print("Currently Blocked IPs:")
    print("==============================")
    blocked = list(collection.find({"status": "BLOCKED"}, {"_id": 0, "ip": 1}))
    if not blocked:
        print("No blocked IPs found!")
        return []
    for i, threat in enumerate(blocked):
        print(str(i+1) + ". " + threat.get("ip", "unknown"))
    return blocked

def unblock_ip(ip):
    try:
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        print("Successfully unblocked: " + ip)
        return True
    except:
        print("Failed to unblock: " + ip)
        return False

def rollback_ip(ip):
    if unblock_ip(ip):
        collection.update_many(
            {"ip": ip},
            {"$set": {
                "status": "ROLLED_BACK",
                "rollback_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }}
        )
        print("MongoDB updated - Status set to ROLLED_BACK")
        print("Rollback complete for: " + ip)
        return True
    return False

def main():
    print("==============================")
    print("SOC Analyst Rollback Tool")
    print("==============================")
    blocked = show_blocked_ips()
    if not blocked:
        return
    print("\nEnter IP to unblock or type 'exit' to quit:")
    ip = input("IP: ")
    if ip == "exit":
        print("Exiting rollback tool!")
        return
    print("\nRolling back: " + ip)
    rollback_ip(ip)

main()
