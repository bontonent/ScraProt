import subprocess
import json
import time
import os

def build_waf_profile(domain, timeout_seconds=30):
    """
    Scans a domain using wafw00f with a configurable timeout.
    """
    profile = {"domain": domain, "timestamp": time.time(), "data": {}}
    url = f"https://{domain}"

    temp_waf_output = f"{domain}_wafw00f_temp.json"

    print(f"[*] Running wafw00f scan against {url} (Timeout: {timeout_seconds}s)...")

    try:
        # Added the 'timeout' parameter (in seconds)
        process = subprocess.run(
            ["wafw00f", url, "-a", "-o", temp_waf_output],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds
        )

        if os.path.exists(temp_waf_output):
            with open(temp_waf_output, "r") as f:
                profile["data"]["wafw00f"] = json.load(f)

            os.remove(temp_waf_output)
        else:
            profile["data"]["wafw00f"] = {
                "error": "Failed to detect WAF or generate JSON output.",
                "cli_output": process.stdout.strip()
            }

    except subprocess.TimeoutExpired:
        # Handle process timeout
        profile["data"]["wafw00f"] = {
            "error": f"Execution timed out after {timeout_seconds} seconds."
        }
        # Clean up temporary output file if it was created before timing out
        if os.path.exists(temp_waf_output):
            os.remove(temp_waf_output)

    except FileNotFoundError:
        profile["data"]["wafw00f"] = {
            "error": "wafw00f executable not found. Ensure it is installed and available in PATH."
        }
    except Exception as e:
        profile["data"]["wafw00f"] = {"error": str(e)}

    return profile

if __name__ == "__main__":
    domain = "ffp.nl"
    # Example setting a 15-second timeout limit
    result = build_waf_profile(domain, timeout_seconds=60)
    print(result)
