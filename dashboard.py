
# Final version - Week 4 complete - Threat Intelligence Platform
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
    <title>SIEM Dashboard</title>
    <style>
        body { background: #0a0a1a; color: white; font-family: Arial; padding: 20px; }
        h1 { color: #00ff88; text-align: center; }
        h3 { color: #00ff88; }
        .stats { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .stat-box { background: #16213e; padding: 20px; border-radius: 10px; flex: 1; text-align: center; min-width: 150px; }
        .stat-box h2 { font-size: 40px; margin: 0; }
        .critical { color: #ff4444; }
        .high { color: #ff8800; }
        .medium { color: #ffcc00; }
        .low { color: #00ff88; }
        .blocked { color: #ff4444; }
        .rolled { color: #00ff88; }
        .search-bar { width: 100%; padding: 10px; margin: 10px 0; background: #16213e; border: 1px solid #00ff88; color: white; border-radius: 5px; font-size: 16px; }
        .filter-bar { display: flex; gap: 10px; margin: 10px 0; flex-wrap: wrap; }
        .filter-btn { padding: 8px 16px; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #16213e; padding: 12px; text-align: left; color: #00ff88; }
        td { padding: 10px; border-bottom: 1px solid #16213e; font-size: 12px; word-break: break-all; }
        tr:hover { background: #16213e; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
        .badge-critical { background: #ff4444; }
        .badge-high { background: #ff8800; }
        .badge-medium { background: #ffcc00; color: black; }
        .badge-low { background: #00ff88; color: black; }
        .badge-blocked { background: #ff4444; }
        .badge-rolled { background: #00ff88; color: black; }
        .badge-active { background: #ff8800; }
    </style>
</head>
<body>
    <h1>Threat Intelligence Platform - SIEM Dashboard</h1>
    <p style="text-align:center;color:#888">Infotact Solutions and Co. | Cybersecurity Internship Project</p>

    <h3>Threat Summary</h3>
    <div class="stats">
        <div class="stat-box">
            <h2>{{ total }}</h2>
            <p>Total Threats</p>
        </div>
        <div class="stat-box">
            <h2 class="critical">{{ critical }}</h2>
            <p>Critical</p>
        </div>
        <div class="stat-box">
            <h2 class="high">{{ high }}</h2>
            <p>High</p>
        </div>
        <div class="stat-box">
            <h2 class="medium">{{ medium }}</h2>
            <p>Medium</p>
        </div>
        <div class="stat-box">
            <h2 class="blocked">{{ blocked }}</h2>
            <p>Blocked</p>
        </div>
        <div class="stat-box">
            <h2 class="rolled">{{ rolled_back }}</h2>
            <p>Rolled Back</p>
        </div>
    </div>

    <h3>Search and Filter</h3>
    <input class="search-bar" type="text" id="searchInput"
    placeholder="Search by IP, domain, threat type, source..."
    onkeyup="filterTable()">

    <div class="filter-bar">
        <button class="filter-btn badge-critical" onclick="filterRisk('Critical')">Critical</button>
        <button class="filter-btn badge-high" onclick="filterRisk('High')">High</button>
        <button class="filter-btn badge-medium" onclick="filterRisk('Medium')">Medium</button>
        <button class="filter-btn badge-low" onclick="filterRisk('Low')">Low</button>
        <button class="filter-btn badge-blocked" onclick="filterStatus('BLOCKED')">Blocked</button>
        <button class="filter-btn badge-rolled" onclick="filterStatus('ROLLED_BACK')">Rolled Back</button>
        <button class="filter-btn" style="background:#00ff88;color:black" onclick="showAll()">All</button>
    </div>

    <h3>Threat Intelligence Table</h3>
    <table id="threatTable">
        <tr>
            <th>Indicator</th>
            <th>Threat Type</th>
            <th>Source</th>
            <th>Severity</th>
            <th>Risk Score</th>
            <th>Risk Level</th>
            <th>Status</th>
        </tr>
        {% for threat in threats %}
        <tr class="threat-row"
            data-risk="{{ threat.get('risk_level', '') }}"
            data-status="{{ threat.get('status', 'ACTIVE') }}">
            <td>{{ threat.get('ip', 'unknown') }}</td>
            <td>{{ threat.get('threat', 'unknown') }}</td>
            <td>{{ threat.get('source', 'unknown') }}</td>
            <td>{{ threat.get('severity', 'unknown') }}</td>
            <td>{{ threat.get('risk_score', 'N/A') }}</td>
            <td><span class="badge badge-{{ threat.get('risk_level', 'low')|lower }}">
                {{ threat.get('risk_level', 'N/A') }}</span></td>
            <td><span class="badge badge-{{ threat.get('status', 'active')|lower }}">
                {{ threat.get('status', 'ACTIVE') }}</span></td>
        </tr>
        {% endfor %}
    </table>

    <script>
        function filterTable() {
            var input = document.getElementById("searchInput").value.toLowerCase();
            var rows = document.getElementsByClassName("threat-row");
            for (var i = 0; i < rows.length; i++) {
                var text = rows[i].innerText.toLowerCase();
                rows[i].style.display = text.includes(input) ? "" : "none";
            }
        }

        function filterRisk(level) {
            var rows = document.getElementsByClassName("threat-row");
            for (var i = 0; i < rows.length; i++) {
                if (rows[i].getAttribute("data-risk") === level) {
                    rows[i].style.display = "";
                } else {
                    rows[i].style.display = "none";
                }
            }
        }

        function filterStatus(status) {
            var rows = document.getElementsByClassName("threat-row");
            for (var i = 0; i < rows.length; i++) {
                if (rows[i].getAttribute("data-status") === status) {
                    rows[i].style.display = "";
                } else {
                    rows[i].style.display = "none";
                }
            }
        }

        function showAll() {
            var rows = document.getElementsByClassName("threat-row");
            for (var i = 0; i < rows.length; i++) {
                rows[i].style.display = "";
            }
        }
    </script>
</body>
</html>
'''

@app.route("/")
def dashboard():
    threats = list(collection.find({}, {"_id": 0}))
    total = len(threats)
    critical = len([t for t in threats if t.get("risk_level") == "Critical"])
    high = len([t for t in threats if t.get("risk_level") == "High"])
    medium = len([t for t in threats if t.get("risk_level") == "Medium"])
    blocked = len([t for t in threats if t.get("status") == "BLOCKED"])
    rolled_back = len([t for t in threats if t.get("status") == "ROLLED_BACK"])
    return render_template_string(HTML, threats=threats, total=total,
        critical=critical, high=high, medium=medium,
        blocked=blocked, rolled_back=rolled_back)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
