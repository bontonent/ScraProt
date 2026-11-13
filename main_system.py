import os
from pymongo import MongoClient
from dotenv import load_dotenv

import waf_scanner
import checker
import PredictLeads
import DomScan
import open_intel
import open_recon

# Load environment variables from .env file
load_dotenv()

class ScraProt:
    def __init__(self, url="https://www.colorhexa.com/f5f6fa"):
        print(f"Raw input: {url}")

        # 1. Delete https:// or http://
        if url.startswith("https://"):
            url = url[8:]
        elif url.startswith("http://"):
            url = url[7:]

        # 2. Divide into two items after the first '/'
        if "/" in url:
            parts = url.split("/", 1)
            self.domain = parts[0]             # Everything before the first '/'
            self.browser = "/" + parts[1]      # The '/' and everything after it
        else:
            self.domain = url
            self.browser = "/"

        # 3. Strip "www." from the domain for API compatibility
        if self.domain.startswith("www."):
            self.domain = self.domain[4:]

        print(f"Parsed Domain: {self.domain}")
        print(f"Parsed Browser: {self.browser}")

        # .env credentials (rest of your code below)
        # .env credentials
        self.db_user = os.getenv("user_mDB")
        self.db_password = os.getenv("password_mDB")
        self.predictlead_key = os.getenv("predictlead_Key")
        self.predictlead_token = os.getenv("predictlead_Token")
        self.domscan_api = os.getenv("domscan_API")

    def connect_mongodb(self):
        # Dynamically build the URI to actually use the .env credentials
        if self.db_user and self.db_password:
            uri = f"mongodb://{self.db_user}:{self.db_password}@localhost:27017/"
        else:
            uri = "mongodb://localhost:27017/"

        try:
            client = MongoClient(uri)
            client.admin.command('ping')
            db = client["scraprot"]
            return db
        except Exception as e:
            print(f"[-] Error connecting to MongoDB: {e}")
            return None

    def _fetch_and_save(self, db, collection_name, fetch_function, *args):
        """
        Reusable helper method to check the database, skip if data exists,
        or fetch and save if it does not.
        """
        collection = db.get_collection(collection_name)
        existing_record = collection.find_one({"domain": self.domain})

        if existing_record:
            print(f"[*] {collection_name.capitalize()} data for {self.domain} already exists. Skipping.")
            return existing_record

        print(f"[*] No existing data found for {self.domain} in {collection_name}. Fetching...")

        # Execute the passed scanning/fetching function with its specific arguments
        result = fetch_function(*args)

        if result:
            collection.replace_one(
                {"domain": result.get("domain", self.domain)},
                result,
                upsert=True
            )
        return result

    def main(self):
        db = self.connect_mongodb()
        if db is None:
            return

        print("[+] Successfully connected to the 'scraprot' database!")
        print("[i] Collections found:", db.list_collection_names())

        # 1. WAFw00f
        self._fetch_and_save(db, "wafw00f", waf_scanner.build_waf_profile, self.domain)

        # 2. Checker (Playwright local DOM/Header analysis)
        self._fetch_and_save(db, "checker", checker.main, self.domain, self.browser)

        # 3. PredictLeads (Tech stack API)
        self._fetch_and_save(
            db,
            "predictleads",
            PredictLeads.main,
            self.domain, self.predictlead_key, self.predictlead_token
        )

        # 4. DomScan (Existing commercial API)
        self._fetch_and_save(
            db,
            "domscan",
            DomScan.build_target_profile,
            self.domain, self.domscan_api
        )

        # 5. Open Intel (Free APIs for DNS, SSL, and Headers)
        self._fetch_and_save(
            db,
            "open_intel",
            open_intel.gather_open_intel,
            self.domain
        )

        self._fetch_and_save(
            db,
            "open_recon",
            open_recon.build_open_profile,
            self.domain
        )


if __name__ == "__main__":
    scraper = ScraProt()
    scraper.main()
