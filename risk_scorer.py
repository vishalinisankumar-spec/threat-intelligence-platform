from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intelligence"]
collection = db["threats"]

def calculate_risk_score(threat):
    score = 0
    threat_type = threat.get("threat", "").lower()
    severity = threat.get("severity", "").lower()
    source = threat.get("source", "").lower()

    # Score based on threat type
    if "botnet" in threat_type:
        score += 10
    elif "malicious" in threat_type:
        score += 9
    elif "phishing" in threat_type:
        score += 8
    elif "malware" in threat_type:
        score += 7
    elif "suspicious" in threat_type:
        score += 5
    else:
        score += 3

    # Score based on severity
    if severity == "high":
        score += 5
    elif severity == "medium":
        score += 3
    elif severity == "low":
        score += 1

    # Score based on source
    if source == "feodotracker":
        score += 5
    elif source == "alienvault otx":
        score += 4
    elif source == "virustotal":
        score += 3

    # Cap score at 10
    if score > 10:
        score = 10

    return score

def assign_risk_level(score):
    if score >= 9:
        return "Critical"
    elif score >= 7:
        return "High"
    elif score >= 5:
        return "Medium"
    else:
        return "Low"

def update_risk_scores():
    print("Starting Risk Scoring...")
    print("==============================")
    threats = list(collection.find())
    updated = 0
    for threat in threats:
        score = calculate_risk_score(threat)
        risk_level = assign_risk_level(score)
        collection.update_one(
            {"_id": threat["_id"]},
            {"$set": {
                "risk_score": score,
                "risk_level": risk_level
            }}
        )
        print("Updated: " + str(threat.get("ip", "unknown")) + " | Score: " + str(score) + " | Level: " + risk_level)
        updated += 1
    print("==============================")
    print("Total threats scored: " + str(updated))
    print("Risk Scoring Complete!")

update_risk_scores()
