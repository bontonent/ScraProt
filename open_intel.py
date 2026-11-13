import requests
import time

def gather_open_intel(domain):
    profile = {"domain": domain, "timestamp": time.time(), "data": {}}

    # 1. Google DoH API
    try:
        dns_url = f"https://dns.google/resolve?name={domain}&type=TXT"
        dns_res = requests.get(dns_url, timeout=10)
        if dns_res.ok:
            profile["data"]["google_dns"] = dns_res.json().get("Answer", [])
        else:
            profile["data"]["google_dns"] = {"error": f"HTTP {dns_res.status_code}"}
    except Exception as e:
        profile["data"]["google_dns"] = {"error": str(e)}

    # 2. Mozilla Observatory API
    try:
        obs_url = f"https://http-observatory.security.mozilla.org/api/v1/analyze?host={domain}"
        # Mozilla requires hidden=true as form data to bypass certain blocks
        obs_res = requests.post(obs_url, data={"hidden": "true"}, timeout=15)
        if obs_res.ok:
            profile["data"]["mozilla_observatory"] = obs_res.json()
        else:
            profile["data"]["mozilla_observatory"] = {"error": f"HTTP {obs_res.status_code}: {obs_res.text}"}
    except Exception as e:
        profile["data"]["mozilla_observatory"] = {"error": str(e)}

    # 3. Qualys SSL Labs API (With Polling)
    try:
        ssl_url = f"https://api.ssllabs.com/api/v3/analyze?host={domain}&fromCache=on&all=done"
        print(f"[*] Initiating SSL Labs scan for {domain}. This may take a moment...")

        max_retries = 15 # Poll up to 15 times (approx 2.5 minutes)
        for attempt in range(max_retries):
            ssl_res = requests.get(ssl_url, timeout=15)
            if not ssl_res.ok:
                profile["data"]["ssl_labs"] = {"error": f"HTTP {ssl_res.status_code}"}
                break

            ssl_data = ssl_res.json()
            status = ssl_data.get("status")

            if status == "READY" or status == "ERROR":
                profile["data"]["ssl_labs"] = ssl_data
                break
            elif status in ["DNS", "IN_PROGRESS"]:
                print(f"    - Scan in progress (Status: {status}). Waiting 10 seconds...")
                time.sleep(10)
            else:
                profile["data"]["ssl_labs"] = {"error": f"Unknown status: {status}"}
                break
        else:
            profile["data"]["ssl_labs"] = {"error": "SSL Labs scan timed out after 2.5 minutes."}

    except Exception as e:
        profile["data"]["ssl_labs"] = {"error": str(e)}

    # 4. RDAP (Domain Registration Data)
    try:
        # rdap.org acts as a bootstrap server that redirects to the correct authoritative RDAP server
        rdap_url = f"https://rdap.org/domain/{domain}"
        rdap_res = requests.get(rdap_url, timeout=10)
        if rdap_res.ok:
            rdap_json = rdap_res.json()
            # Extracting only the most relevant fields to save LLM context space
            profile["data"]["rdap"] = {
                "handle": rdap_json.get("handle"),
                "events": rdap_json.get("events", []),
                "status": rdap_json.get("status", [])
            }
        else:
            profile["data"]["rdap"] = {"error": f"HTTP {rdap_res.status_code}"}
    except Exception as e:
        profile["data"]["rdap"] = {"error": str(e)}

    return profile

if __name__ == "__main__":
    domain = "colorhexa.com"
    result = gather_open_intel(domain)
    import json
    print(json.dumps(result, indent=4))
