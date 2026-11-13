import requests
import time

def build_open_profile(domain):
    """
    Gathers DNS, RDAP, and HTTP Header data using free, public endpoints.
    Returns a dictionary formatted for MongoDB insertion.
    """
    profile = {
        "domain": domain,
        "timestamp": time.time(),
        "data": {}
    }

    # 1. DNS Records via Cloudflare DoH (No API key needed)
    try:
        dns_res = requests.get(
            f"https://cloudflare-dns.com/dns-query?name={domain}&type=ANY",
            headers={"Accept": "application/dns-json"},
            timeout=10
        )
        if dns_res.status_code == 200:
            profile["data"]["dns"] = dns_res.json().get("Answer", [])
        else:
            profile["data"]["dns"] = {"error": f"HTTP {dns_res.status_code}"}
    except requests.RequestException as e:
        profile["data"]["dns"] = {"error": str(e)}

    # 2. Registration Data via RDAP (Standardized WHOIS replacement)
    try:
        rdap_res = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers={"Accept": "application/rdap+json"},
            timeout=10
        )
        if rdap_res.status_code == 200:
            # Extracting just the useful bits to save MongoDB space
            rdap_data = rdap_res.json()
            profile["data"]["rdap"] = {
                "entities": rdap_data.get("entities", []),
                "events": rdap_data.get("events", []),
                "nameservers": rdap_data.get("nameservers", [])
            }
        else:
            profile["data"]["rdap"] = {"error": f"HTTP {rdap_res.status_code}"}
    except requests.RequestException as e:
        profile["data"]["rdap"] = {"error": str(e)}

    # 3. HTTP Security Headers Analysis
    try:
        # Using a standard user agent to avoid basic blocks
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        http_res = requests.get(f"https://{domain}", headers=headers, timeout=10)

        # Convert CaseInsensitiveDict to standard dict for MongoDB
        profile["data"]["headers"] = dict(http_res.headers)
        profile["data"]["status_code"] = http_res.status_code
    except requests.RequestException as e:
        profile["data"]["headers"] = {"error": str(e)}

    return profile

if __name__ == "__main__":
    import json
    # Test the module directly
    test_data = build_open_profile("deere.com")
    print(json.dumps(test_data, indent=4))
