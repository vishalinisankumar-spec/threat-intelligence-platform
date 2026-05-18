from flask import Flask, render_template_string
from pymongo import MongoClient

app = Flask(__name__)

client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intelligence"]
collection = db["threats"]

HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Threat Intelligence Dashboard</title>
    <style>
        body { background: #1a1a2e; color: white; font-family: Arial; padding: 20px; }
        h1 { color: #e94560; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #16213e; padding: 12px; text-align: left; color: #e94560; }
        td { padding: 10px; border-bottom: 1px solid #16213e; }
        tr:hover { background: #16213e; }
        .high { color: #e94560; font-weight: bold; }
        .medium { color: #f5a623; }
        .low { color: #7ed321; }
    </style>
</head>
<body>
    <h1>Threat Intelligence Dashboard</h1>
    <p>Total Threats: {{ threats|length }}</p>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Threat Type</th>
            <th>Severity</th>
        </tr>
        {% for threat in threats %}
        <tr>
            <td>{{ threat.ip }}</td>
            <td>{{ threat.threat }}</td>
            <td class="{{ threat.severity|lower }}">{{ threat.severity }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
'''

@app.route("/")
def dashboard():
    threats = list(collection.find({}, {"_id": 0}))
    return render_template_string(HTML, threats=threats)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
