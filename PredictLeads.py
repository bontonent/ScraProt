import requests
import time

def main(domain, predictlead_Key, predictlead_Token):
    url = f"https://predictleads.com/api/v3/companies/{domain}/technology_detections"

    headers = {
        "X-Api-Key": predictlead_Key,
        "X-Api-Token": predictlead_Token,
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers)

    print(f"Status Code: {response.status_code}")

    result = {
        "domain": domain,
        "timestamp": time.time(),
        "data": None
    }

    if response.status_code == 200:
        data = response.json()
        result["data"] = data
    else:
        print("Error:", response.text)
        result["data"] = response.text

    return result
