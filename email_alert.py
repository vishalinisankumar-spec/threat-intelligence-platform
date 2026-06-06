import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime
import os

load_dotenv()
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER")

client = MongoClient("mongodb://localhost:27017/")
db = client["threat_intelligence"]
collection = db["threats"]

def send_alert(critical_threats):
    subject = "CRITICAL THREAT ALERT - Threat Intelligence Platform"
    body = """
CRITICAL THREAT ALERT
==============================
Time: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """

The following Critical threats have been detected:

"""
    for threat in critical_threats[:10]:
        body += "IP/Domain: " + str(threat.get("ip", "unknown")) + "\n"
        body += "Threat Type: " + str(threat.get("threat", "unknown")) + "\n"
        body += "Source: " + str(threat.get("source", "unknown")) + "\n"
        body += "Risk Score: " + str(threat.get("risk_score", "unknown")) + "\n"
        body += "------------------------------\n"

    body += """
Total Critical Threats: """ + str(len(critical_threats)) + """

Please review the SIEM dashboard immediately!
http://192.168.232.128:5000

This is an automated alert from Threat Intelligence Platform.
Infotact Solutions and Co.
"""

    msg = MIMEMultipart()
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        server.quit()
        print("Alert email sent successfully!")
        print("Sent to: " + EMAIL_RECEIVER)
        return True
    except Exception as e:
        print("Failed to send email: " + str(e))
        return False

def check_and_alert():
    print("Checking for Critical threats...")
    critical_threats = list(collection.find({"risk_level": "Critical"}, {"_id": 0}))
    print("Critical threats found: " + str(len(critical_threats)))
    if critical_threats:
        print("Sending alert email...")
        send_alert(critical_threats)
    else:
        print("No critical threats found!")

check_and_alert()
