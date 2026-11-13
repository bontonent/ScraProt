import time
import tldextract
import requests

def main(domain_or_url, predictlead_Key, predictlead_Token):
    # Automatically extract the root domain (e.g., 'ria.com')
    # whether the user passed a URL, a subdomain, or a clean domain.
    extracted = tldextract.extract(domain_or_url)
    if extracted.domain and extracted.suffix:
        clean_domain = f"{extracted.domain}.{extracted.suffix}"
    else:
        clean_domain = domain_or_url  # fallback

    url = f"https://predictleads.com/api/v3/companies/{clean_domain}/technology_detections"

    headers = {
        "X-Api-Key": predictlead_Key,
        "X-Api-Token": predictlead_Token,
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers)

    print(f"Status Code: {response.status_code}")

    result = {
        "domain": domain_or_url,
        "timestamp": time.time(),
        "data": None
    }

    if response.status_code == 200:
        result["data"] = response.json()
    else:
        print("Error:", response.text)
        result["data"] = response.text

    return result

# if __name__ == "__main__":
#     domain = "https://auto.ria.com/search/?search_type=2"
#     predictlead_Key = "your_key"
#     predictlead_Token = "your_token"
#     result = main(domain, predictlead_Key, predictlead_Token)
#     print(result)
