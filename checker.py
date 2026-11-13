import asyncio
import json
import re
import socket
import ssl
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

# ==============================================================================
# CONFIGURATION & SIGNATURES
# ==============================================================================

HEADERS = {
    "User-Agent": "WebsiteSecurityAudit/1.0 (authorized defensive testing)"
}

PROTECTION_SIGNATURES = {
    "Cloudflare": ["cloudflare", "cf-ray", "__cf_bm", "cf_clearance", "cdn-cgi"],
    "Akamai": ["akamai", "ak_bmsc", "bm_sz", "akamai bot manager"],
    "Imperva": ["incapsula", "imperva", "visid_incap", "incap_ses"],
    "DataDome": ["datadome", "dd_cookie"],
    "Sucuri": ["sucuri", "x-sucuri-id"],
    "reCAPTCHA": ["google.com/recaptcha", "g-recaptcha", "grecaptcha"],
    "hCaptcha": ["hcaptcha.com", "h-captcha"],
    "Cloudflare Turnstile": ["challenges.cloudflare.com/turnstile", "cf-turnstile"]
}

FRAMEWORK_SIGNATURES = {
    "React": ["__react", "react-dom", "reactroot", "data-reactroot"],
    "Next.js": ["__next_data__", "/_next/", "next.js"],
    "Vue": ["__vue__", "data-v-"],
    "Angular": ["ng-version", "ng-app"],
    "Svelte": ["svelte-"]
}

# ==============================================================================
# DETECTION FUNCTIONS
# ==============================================================================

def check_tls(url):
    """Gathers TLS certificate information passively."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {"error": "Website does not use HTTPS"}

    host = parsed.hostname
    port = parsed.port or 443

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure:
                cert = secure.getpeercert()
                return {
                    "version": secure.version(),
                    "expires": cert.get("notAfter", "Unknown")
                }
    except Exception as e:
        return {"error": str(e)}

def analyze_html_content(html, base_url, response_headers):
    """Parses the DOM and HTTP headers for structural and defense signatures."""
    soup = BeautifulSoup(html, "html.parser")
    content_lower = html.lower()
    headers_lower = str(response_headers).lower()
    combined_sig_text = content_lower + " " + headers_lower

    data = {
        "detected_wafs_and_captchas": [],
        "detected_frameworks": [],
        "script_count": len(soup.find_all("script")),
        "json_references": [],
        "forms": [],
        "shadow_dom_indicators": False,
        "unique_classes_sample": []
    }

    # 1. WAF & CAPTCHA Signatures
    for provider, signatures in PROTECTION_SIGNATURES.items():
        if any(sig in combined_sig_text for sig in signatures):
            data["detected_wafs_and_captchas"].append(provider)

    # 2. Framework Detection
    for framework, markers in FRAMEWORK_SIGNATURES.items():
        if any(marker in content_lower for marker in markers):
            data["detected_frameworks"].append(framework)

    # 3. JSON and Asset References
    for script in soup.find_all("script"):
        inline = script.string or ""
        for match in re.findall(r'["\']([^"\']+\.json(?:\?[^"\']*)?)["\']', inline, re.I):
            absolute = urljoin(base_url, match)
            data["json_references"].append(absolute)

    # 4. Form and Hidden Field Analysis
    for index, form in enumerate(soup.find_all("form"), 1):
        form_data = {
            "id": index,
            "action": form.get("action"),
            "method": form.get("method", "GET"),
            "has_password_field": bool(form.find("input", {"type": "password"})),
            "hidden_fields": [field.get("name") for field in form.find_all("input", {"type": "hidden"}) if field.get("name")]
        }
        data["forms"].append(form_data)

    # 5. Shadow DOM & Dynamic Indicators
    data["shadow_dom_indicators"] = "attachshadow" in content_lower or len(soup.select("[shadowrootmode]")) > 0

    # 6. Class Obfuscation Sampling
    classes = set()
    for element in soup.find_all(True):
        classes.update(element.get("class", []))
    data["unique_classes_sample"] = list(classes)[:15]

    return data

# ==============================================================================
# PLAYWRIGHT EXECUTION
# ==============================================================================

async def evaluate_target(url, rate_test=False):
    """Uses Playwright to fetch the target and build the JSON profile."""

    # Store the actual Playwright data in a dictionary
    playwright_data = {
        "url": url,
        "tls_info": check_tls(url),
        "http_headers": {},
        "cookies": [],
        "dom_analysis": {},
        "rate_limit_test": "Not Performed"
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(user_agent=HEADERS["User-Agent"])
        page = await context.new_page()

        try:
            # Main Page Evaluation - Changed to domcontentloaded to prevent TimeoutError on complex sites
            response = await page.goto(url, wait_until="domcontentloaded", timeout=25000)

            # Wait a brief moment to allow scripts to execute and DOM to build
            await page.wait_for_timeout(2500)

            if response:
                playwright_data["final_url"] = response.url
                playwright_data["status_code"] = response.status
                playwright_data["http_headers"] = response.headers

                # Fetch cookies established during the session
                playwright_data["cookies"] = await context.cookies()

                # Extract the fully rendered HTML
                html_content = await page.content()
                playwright_data["dom_analysis"] = analyze_html_content(html_content, response.url, response.headers)
            else:
                playwright_data["error"] = "No response received from target."

            # 2. Optional: Light Rate Limit Test
            if rate_test:
                rate_results = []
                for i in range(3):
                    try:
                        res = await page.goto(url, wait_until="commit", timeout=10000)
                        rate_results.append({"attempt": i+1, "status": res.status if res else "Failed"})
                    except Exception as e:
                        rate_results.append({"attempt": i+1, "status": f"Error: {str(e)}"})
                    await page.wait_for_timeout(1000)
                playwright_data["rate_limit_test"] = rate_results

        except PlaywrightTimeoutError:
            playwright_data["error"] = "Playwright Timeout: The site failed to load within the allowed time."
        except Exception as e:
            playwright_data["error"] = f"Evaluation Failed: {str(e)}"
        finally:
            await browser.close()

    return playwright_data


def main(domain_input, path=""):
    """
    Constructs the final dictionary structure specifically for MongoDB insertion.
    """
    # Construct URL properly
    url = f"https://{domain_input}/{path.lstrip('/')}" if not domain_input.startswith("http") else domain_input

    # Extract strictly the root domain name for the MongoDB 'domain' field
    parsed_domain = urlparse(url).netloc.replace("www.", "")

    print(f"[*] Starting Playwright evaluation for: {url}")

    # Run Playwright to get the scrape data
    scraped_data = asyncio.run(evaluate_target(url, rate_test=True))

    # Construct the final MongoDB Document structure
    mongo_document = {
        "domain": parsed_domain,
        "timestamp": time.time(),
        "data": scraped_data
    }

    return mongo_document

if __name__ == "__main__":
    # Ensure proper URL formatting
    target_domain = "shop.deere.com"
    target_path = "/es" # Optional, if you want a specific page

    document = main(target_domain, target_path)

    # Print the resulting Python dictionary (Formatted via json.dumps for readability in console)
    print(json.dumps(document, indent=4))
