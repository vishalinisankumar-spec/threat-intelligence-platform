import requests
from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intelligence"]
collection = db["threats"]
inserted_ips = set()

def insert_threat(ip, threat_type, severity, source):
    if ip in inserted_ips:
        print("Duplicate skipped: " + ip)
        return
    collection.insert_one({"ip": ip, "threat": threat_type, "severity": severity, "source": source})
    inserted_ips.add(ip)
    print("Inserted: " + ip + " | " + threat_type + " | " + source)

def fetch_alienvault():
    print("Fetching from AlienVault OTX...")
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10"
    response = requests.get(url, headers=headers)
    data = response.json()
    print("AlienVault status: " + str(response.status_code))
    count = 0
    for pulse in data.get("results", []):
        for indicator in pulse.get("indicators", []):
            ioc_type = indicator.get("type", "")
            ioc_value = indicator.get("indicator", "")
            if ioc_type in ["IPv4", "URL", "domain", "hostname"]:
                insert_threat(ioc_value, "AlienVault " + ioc_type, "High", "AlienVault OTX")
                count += 1
    print("AlienVault inserted: " + str(count) + " indicators")
    print("AlienVault done!")

def fetch_virustotal():
    print("Fetching from VirusTotal...")
    test_ips = ["1.1.1.1", "8.8.8.8", "185.220.101.1"]
    headers = {"x-apikey": VT_API_KEY}
    for ip in test_ips:
        url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip
        response = requests.get(url, headers=headers)
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        if malicious > 0:
            insert_threat(ip, "Malicious IP", "High", "VirusTotal")
        else:
            insert_threat(ip, "Suspicious IP", "Medium", "VirusTotal")
    print("VirusTotal done!")

def fetch_feodotracker():
    print("Fetching from Feodo Tracker...")
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    response = requests.get(url)
    data = response.json()
    count = 0
    for item in data[:20]:
        ip = item.get("ip_address", "")
        if ip:
            insert_threat(ip, "Botnet C2", "High", "FeodoTracker")
            count += 1
    print("FeodoTracker inserted: " + str(count) + " IPs")
    print("FeodoTracker done!")

print("Starting OSINT Aggregation...")
print("==============================")
fetch_alienvault()
fetch_virustotal()
fetch_feodotracker()
print("==============================")
print("OSINT Aggregation Complete!")
print("Total unique threats inserted: " + str(len(inserted_ips)))
