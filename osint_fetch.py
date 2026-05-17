
import requests

url = "https://api.github.com"

response = requests.get(url)

print("Status Code:", response.status_code)
print("Response:", response.json())

import requests

url = "https://api.github.com"

response = requests.get(url)

data = response.json()

print("GitHub API Status:", response.status_code)
print("Current User URL:", data["current_user_url"])
print("Events URL:", data["events_url"])
print("Repository URL:", data["repository_url"])
