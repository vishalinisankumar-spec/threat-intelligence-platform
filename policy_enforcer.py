from pymongo import MongoClient
import subprocess

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intelligence"]
collection = db["threats"]

def block_ip(ip):
    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        print(f"Blocked IP: {ip}")
    except subprocess.CalledProcessError:
        print(f"Failed to block IP: {ip}")

def enforce_policies():
    print("Starting Policy Enforcer...")
    threats = collection.find()
    count = 0
    for threat in threats:
        ip = threat.get("ip")
        if ip:
            block_ip(ip)
            count += 1
    print(f"Total IPs blocked: {count}")

enforce_policies()
