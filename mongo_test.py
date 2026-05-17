from pymongodb import MongoClient

client = MongoClient("mongodb://localhost:27017/")

db = client["threat_intelligence"]

collection = db["threats"]

data = {
"ip": "1.1.1.1",
"threat": "Suspicious Traffic",
"severity": "Medium"
}

result = collection.insert_one(data)

print("Threat stored successfully")
print("Inserted ID:", result.inserted_id)
