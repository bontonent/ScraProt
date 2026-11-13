import os
import sys
import json
import requests
from flask import Flask, render_template, request, jsonify
from pymongo import MongoClient
from dotenv import load_dotenv

# Import ScraProt from main_system.py
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from main_system import ScraProt

load_dotenv()
app = Flask(__name__, template_folder="templates", static_folder="static")

client = MongoClient("mongodb://localhost:27017/")
db = client["scraprot"]

@app.route("/")
def index():
    # Get all distinct domains that have already been scanned to populate dropdowns
    scanned_domains = db.get_collection("wafw00f").distinct("domain")

    # If the user searched a domain, fetch its data to display
    view_domain = request.args.get("view_domain", "")
    domain_data = None

    if view_domain:
        domain_data = {
            "waf": db.get_collection("wafw00f").find_one({"domain": view_domain}, {"_id": 0}),
            "checker": db.get_collection("checker").find_one({"domain": view_domain}, {"_id": 0}),
            "predictleads": db.get_collection("predictleads").find_one({"domain": view_domain}, {"_id": 0}),
            "domscan": db.get_collection("domscan").find_one({"domain": view_domain}, {"_id": 0}),
            "open_intel": db.get_collection("open_intel").find_one({"domain": view_domain}, {"_id": 0}),
            "open_recon": db.get_collection("open_recon").find_one({"domain": view_domain}, {"_id": 0}),
        }

    return render_template("index.html", domains=scanned_domains, view_domain=view_domain, data=domain_data)

@app.route("/api/scan", methods=["POST"])
def scan_new():
    raw_input = request.json.get("domain")
    if not raw_input:
        return jsonify({"error": "No URL provided"}), 400

    try:
        # Pass the raw input directly to ScraProt; it will parse it internally
        scraper = ScraProt(url=raw_input)
        scraper.main()

        return jsonify({"message": f"Successfully scanned {scraper.domain}. Reloading..."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/analyze", methods=["POST"])
def analyze_domain():
    domain = request.json.get("domain")
    if not domain:
        return jsonify({"error": "No domain selected"}), 400

    # 1. Align the database pull with your actual MongoDB collections created by ScraProt
    scraped_data = {
        "waf": db.get_collection("wafw00f").find_one({"domain": domain}, {"_id": 0}),
        "checker": db.get_collection("checker").find_one({"domain": domain}, {"_id": 0}),
        "predictleads": db.get_collection("predictleads").find_one({"domain": domain}, {"_id": 0}),
        "domscan": db.get_collection("domscan").find_one({"domain": domain}, {"_id": 0}),
        "open_intel": db.get_collection("open_intel").find_one({"domain": domain}, {"_id": 0}),
        "open_recon": db.get_collection("open_recon").find_one({"domain": domain}, {"_id": 0}),
    }

    # 2. Clean heavy data to prevent the LLM from overflowing its context and failing
    # Clean the Playwright/Checker data
    if scraped_data.get("checker") and "data" in scraped_data["checker"]:
        dom_analysis = scraped_data["checker"]["data"].get("dom_analysis", {})
        dom_analysis.pop("unique_classes_sample", None)
        dom_analysis.pop("json_references", None)

    # Clean DomScan if it has raw HTML or heavy arrays
    if scraped_data.get("domscan") and "data" in scraped_data["domscan"]:
        scraped_data["domscan"]["data"].pop("raw_html", None)
        scraped_data["domscan"]["data"].pop("links", None)
        scraped_data["domscan"]["data"].pop("scripts", None)

    raw_json = json.dumps(scraped_data)

    # Initialize the Markdown report
    md_report = f"# Comprehensive Security Analysis Report: {domain}\n\n"

    stage_titles = [
        "1. DNS & Infrastructure Overview",
        "2. Transport Security & HTTP Headers (Rules R1-R10)",
        "3. Session, Disclosure, & Email Security (Rules R11-R14)",
        "4. Anti-Scraping Protection (Vectors 1-7)",
        "5. Anti-Scraping Protection (Vectors 8-14)",
        "6. Final Assessment & Remediation Checklist"
    ]

    # Initialize the Conversation History (Memory)
    chat_history = [
        {
            "role": "system",
            "content": "You are a rigid data extractor and cybersecurity analyst. Output ONLY the requested Markdown formatting. DO NOT repeat data from previous sections. DO NOT output conversational filler, greetings, or conclusions."
        }
    ]

    # Sequentially call Ollama for all 6 stages, keeping memory intact
    for i in range(1, 7):
        prompt_path = os.path.join(os.path.dirname(__file__), f'prompt_{i}.txt')

        try:
            with open(prompt_path, 'r', encoding='utf-8') as f:
                base_prompt = f.read()
        except FileNotFoundError:
            print(f"[!] Warning: Could not find {prompt_path}.")
            base_prompt = "Analyze the provided security data strictly focusing on this stage's metrics."

        # Stage 1: Feed the heavy JSON AND the first prompt
        if i == 1:
            user_content = f"### DATA PAYLOAD:\n```json\n{raw_json}\n```\n\n### STAGE 1 INSTRUCTIONS:\n{base_prompt}"
        # Stage 6: Remind it to use all previous history
        elif i == 6:
            user_content = f"### STAGE 6 INSTRUCTIONS:\n{base_prompt}\n\nCRITICAL: Use all the intelligence and analysis you generated in Stages 1 through 5 to create a highly accurate final description."
        # Stages 2-5: Just feed the prompt (JSON is already in memory!)
        else:
            user_content = f"### STAGE {i} INSTRUCTIONS:\n{base_prompt}"

        # Add the current prompt to the history
        chat_history.append({"role": "user", "content": user_content})

        try:
            response = requests.post('http://localhost:11434/api/chat', json={
                "model": "qwen2.5:14b",
                "messages": chat_history, # Pass the entire history so it remembers!
                "stream": False,
                "options": {
                    "num_ctx": 16384,
                    "temperature": 0.0,
                    "top_p": 0.1,
                    "repeat_penalty": 1.15
                }
            })

            if response.status_code == 200:
                stage_content = response.json().get("message", {}).get("content", "").strip()

                # Append the generated report to the Markdown file
                md_report += f"## {stage_titles[i-1]}\n{stage_content}\n\n"

                # CRITICAL: Append the AI's answer to the chat history so it remembers it for the next loop!
                chat_history.append({"role": "assistant", "content": stage_content})
            else:
                return jsonify({"error": f"Ollama error at Stage {i}: {response.text}"}), 500

        except requests.exceptions.ConnectionError:
            return jsonify({"error": "Could not connect to Ollama. Is it running?"}), 500

    # Save the combined markdown report to a file
    report_filename = f"{domain}_security_report.md"
    report_path = os.path.join(os.path.dirname(__file__), report_filename)

    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(md_report)
    except Exception as e:
        print(f"[!] Error saving MD file: {e}")

    return jsonify({"report": md_report, "file_saved": report_filename})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
