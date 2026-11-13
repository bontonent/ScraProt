import requests
import json
import time

def build_target_profile(domain, api_key):
    headers = {"X-API-Key": api_key, "Accept": "application/json"}
    base_url = "https://domscan.net/v1"

    # Map out the specific detection endpoints to query
    endpoints = {
        "dns": f"{base_url}/dns?domain={domain}&type=ALL",
        "reputation": f"{base_url}/reputation?domain={domain}",
        "technologies": f"{base_url}/technologies?domain={domain}",
        "headers": f"{base_url}/headers?domain={domain}",
        "robots": f"{base_url}/robots?domain={domain}"
    }

    profile = {"domain": domain, "timestamp": time.time(), "data": {}}

    for key, url in endpoints.items():
        try:
            res = requests.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                profile["data"][key] = res.json()
        except requests.exceptions.RequestException:
            profile["data"][key] = {"error": "Request failed"}

    return profile

if __name__ == "__main__":
    domain = "deere.com"
    api_key = "dsk_dbe04c65343f840aa209e6ac3d34dc846ae602c304ce7a93a92bba81d3281136"
    build_target_profile(domain,api_key)
