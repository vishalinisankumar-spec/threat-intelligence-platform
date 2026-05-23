import requests
import json
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
        print(f"Duplicate skipped: {ip}")
        return
    collection.insert_one({
        "ip": ip,
        "threat": threat_type,
        "severity": severity,
        "source": source
    })
    inserted_ips.add(ip)
    print(f"Inserted: {ip} | {threat_type} | {severity} | {source}")

def fetch_threatfox():
    print("\nFetching from ThreatFox...")
    try:
        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {"query": "get_iocs", "days": 1}
        response = requests.post(url, json=payload)
        data = response.json()
        status = data.get("query_status", "no status")
        print(f"ThreatFox status: {status}")
        if status == "ok":
            for item in data["data"]:
                ip = item.get("ioc_value", "")
                if ":" in ip:
                    ip = ip.split(":")[0]
                threat_type = item.get("threat_type", "unknown")
                insert_threat(ip, threat_type, "High", "ThreatFox")
        print("ThreatFox done!")
    except Exception as e:
        print(f"ThreatFox error: {e}")

def fetch_alienvault():
    print("\nFetching from AlienVault OTX...")
    try:
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=5"
        response = requests.get(url, headers=headers)
        data = response.json()
        for pulse in data.get("results", []):
            for indicator in pulse.get("indicators", []):
                if indicator.get("type") == "IPv4":
                    ip = indicator.get("indicator", "")
                    insert_threat(ip, "AlienVault Threat", "High", "AlienVault OTX")
        print("AlienVault done!")
    except Exception as e:
        print(f"AlienVault error: {e}")

def fetch_virustotal():
    print("\nFetching from VirusTotal...")
    try:
        test_ips = ["1.1.1.1", "8.8.8.8", "185.220.101.1"]
        headers = {"x-apikey": VT_API_KEY}
        for ip in test_ips:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            response = requests.get(url, headers=headers)
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            if malicious > 0:
                insert_threat(ip, "Malicious IP", "High", "VirusTotal")
            else:
                insert_threat(ip, "Suspicious IP", "Medium", "VirusTotal")
        print("VirusTotal done!")
    except Exception as e:
        print(f"VirusTotal error: {e}")

print("Starting OSINT Aggregation...")
print("==============================")
fetch_threatfox()
fetch_alienvault()
fetch_virustotal()
print("\n==============================")
print("OSINT Aggregation Complete!")
print(f"Total unique threats inserted: {len(inserted_ips)}")
